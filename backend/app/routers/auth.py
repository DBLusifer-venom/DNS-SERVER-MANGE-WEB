from datetime import datetime, timedelta, timezone
import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_db
from ..deps import get_current_user, write_audit
from ..models import User, UserToken
from ..schemas import LoginRequest, RefreshRequest, TokenResponse, UserOut
from ..security import (
    create_access_token,
    generate_refresh_token,
    hash_token,
    refresh_expiry,
    verify_password,
)
from ..services.ratelimit import check_and_record, clear

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    return request.client.host if request.client else None, request.headers.get("user-agent", "")[:255]


def _naive_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=token,
        max_age=settings.refresh_token_expire_days * 86400,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/api/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=settings.cookie_name, path="/api/auth")


def _extract_refresh_token(body: RefreshRequest | None, cookie: str | None) -> str:
    # Explicit body token wins (e.g. API clients); the cookie is the
    # browser convenience. Either path goes through rotation+reuse checks.
    if body and body.refresh_token:
        return body.refresh_token
    if cookie:
        return cookie
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")


def _rate_limit(request: Request, username: str) -> None:
    """429 when the client IP or username exceeds the failure window.
    Keys are cleared on successful login."""
    ip = request.client.host if request.client else "unknown"
    if not check_and_record(f"ip:{ip}") or not check_and_record(f"user:{username}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many login attempts — try again later",
            headers={"Retry-After": str(settings.rate_limit_window_seconds)},
        )


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _rate_limit(request, body.username)
    user = db.query(User).filter(User.username == body.username).first()
    ip, ua = _client_meta(request)

    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    now = _naive_now()
    if user.locked_until and user.locked_until > now:
        raise HTTPException(
            status.HTTP_423_LOCKED,
            f"Account locked until {user.locked_until.isoformat()}",
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= settings.login_attempt_limit:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_logins = 0
        db.commit()
        write_audit(db, user, "auth.login_failed", "user", user.username, request=request)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")

    if not user.active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Account disabled")

    user.failed_logins = 0
    user.locked_until = None
    family_id = uuid.uuid4().hex
    refresh_token, _ = generate_refresh_token()
    db.add(UserToken(user_id=user.id, token_hash=hash_token(refresh_token), family_id=family_id, expires_at=refresh_expiry(), ip_address=ip, user_agent=ua))
    db.commit()
    write_audit(db, user, "auth.login", "user", user.username, request=request)
    db.commit()
    clear(f"user:{body.username}")
    if request.client:
        clear(f"ip:{request.client.host}")

    access_token, expires_in = create_access_token(user.id)
    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token, expires_in=expires_in)


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    refresh_cookie: str | None = Cookie(default=None, alias=settings.cookie_name),
    db: Session = Depends(get_db),
):
    ip, ua = _client_meta(request)
    token = _extract_refresh_token(body, refresh_cookie)
    token_hash = hash_token(token)
    stored = db.query(UserToken).filter(UserToken.token_hash == token_hash).first()

    if stored is None or stored.expires_at < _naive_now():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    if stored.revoked:
        # Reuse of a rotated-out token: compromise suspected.
        # Revoke the WHOLE token family, not just this one.
        if stored.family_id:
            db.query(UserToken).filter(
                UserToken.family_id == stored.family_id, UserToken.revoked.is_(False)
            ).update({"revoked": True}, synchronize_session=False)
            db.commit()
        write_audit(db, None, "auth.token_reuse", "user", str(stored.user_id), request=request)
        db.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Refresh token reuse detected — all sessions in this family were revoked",
        )

    user = db.get(User, stored.user_id)
    if user is None or not user.active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User inactive or removed")

    stored.revoked = True
    new_refresh, _ = generate_refresh_token()
    db.add(UserToken(user_id=user.id, token_hash=hash_token(new_refresh), family_id=stored.family_id, expires_at=refresh_expiry(), ip_address=ip, user_agent=ua))
    db.commit()
    write_audit(db, user, "auth.refresh", "user", user.username, request=request)
    db.commit()

    access_token, expires_in = create_access_token(user.id)
    _set_refresh_cookie(response, new_refresh)
    return TokenResponse(access_token=access_token, refresh_token=new_refresh, expires_in=expires_in)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    refresh_cookie: str | None = Cookie(default=None, alias=settings.cookie_name),
    db: Session = Depends(get_db),
):
    try:
        token = _extract_refresh_token(body, refresh_cookie)
    except HTTPException:
        _clear_refresh_cookie(response)
        return {"ok": True}
    token_hash = hash_token(token)
    stored = db.query(UserToken).filter(UserToken.token_hash == token_hash).first()
    if stored:
        stored.revoked = True
        db.commit()
    _clear_refresh_cookie(response)
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user