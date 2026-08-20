from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_role, write_audit
from ..models import Server, ServerAssignment, User
from ..schemas import ServerAssignmentsIn, ServerCreate, ServerOut, ServerTestResult, ServerUpdate
from ..security import encrypt_secret
from ..services.bind_control import BindServer, test_server
from ..services.destpolicy import pin_destination, validate_destination

router = APIRouter(prefix="/api/servers", tags=["servers"])
admin = require_role("admin")
admin_or_operator = require_role("admin", "operator")


def _serialize(db: Session, server: Server) -> ServerOut:
    out = ServerOut.model_validate(server)
    out.assigned_user_ids = [
        a.user_id for a in db.query(ServerAssignment).filter(ServerAssignment.server_id == server.id).all()
    ]
    out.pinned_ips = [p for p in (server.pinned_ips or "").split(",") if p]
    return out


def _accessible_server(db: Session, user: User, server_id: int) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    if user.role == "admin":
        return server
    assigned = (
        db.query(ServerAssignment)
        .filter(ServerAssignment.server_id == server_id, ServerAssignment.user_id == user.id)
        .first()
    )
    if assigned is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Server not assigned to you")
    return server


def _validated_host(host: str) -> str:
    try:
        validate_destination(host)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    return host


def _pinned_host(host: str) -> str:
    """Validate host and return the comma-joined pinned IP list (explicit
    per-server allowlist, resolved at registration time)."""
    try:
        return ",".join(pin_destination(host))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


@router.get("", response_model=list[ServerOut])
def list_servers(db: Session = Depends(get_db), user: User = Depends(admin_or_operator)):
    if user.role == "admin":
        servers = db.query(Server).order_by(Server.name).all()
    else:
        servers = (
            db.query(Server)
            .join(ServerAssignment, ServerAssignment.server_id == Server.id)
            .filter(ServerAssignment.user_id == user.id)
            .order_by(Server.name)
            .all()
        )
    return [_serialize(db, s) for s in servers]


@router.post("", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
def create_server(body: ServerCreate, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(admin)):
    if db.query(Server).filter(Server.name == body.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Server name already exists")
    _validated_host(body.host)

    server = Server(
        name=body.name,
        host=body.host,
        notes=body.notes,
        rndc_port=body.rndc_port,
        rndc_key_name=body.rndc_key_name,
        rndc_algorithm=body.rndc_algorithm,
        rndc_secret_enc=encrypt_secret(body.rndc_secret),
        update_port=body.update_port,
        update_key_name=body.update_key_name,
        update_secret_enc=encrypt_secret(body.update_secret),
        pinned_ips=_pinned_host(body.host),
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    write_audit(db, admin_user, "server.create", "server", server.name, request=request)
    db.commit()
    return _serialize(db, server)


@router.get("/{server_id}", response_model=ServerOut)
def get_server(server_id: int, db: Session = Depends(get_db), user: User = Depends(admin_or_operator)):
    return _serialize(db, _accessible_server(db, user, server_id))


@router.patch("/{server_id}", response_model=ServerOut)
def update_server(
    server_id: int,
    body: ServerUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(admin),
):
    server = _get_server_or_404(db, server_id)
    changes = body.model_dump(exclude_unset=True)
    if "host" in changes:
        _validated_host(changes["host"])
        server.pinned_ips = _pinned_host(changes["host"])  # re-pin on host change
    if "name" in changes and changes["name"] != server.name:
        existing = db.query(Server).filter(Server.name == changes["name"]).first()
        if existing:
            raise HTTPException(status.HTTP_409_CONFLICT, "Server name already exists")
        server.name = changes["name"]
    if "rndc_secret" in changes:
        server.rndc_secret_enc = encrypt_secret(changes.pop("rndc_secret"))
    if "update_secret" in changes:
        server.update_secret_enc = encrypt_secret(changes.pop("update_secret"))
    for field, value in changes.items():
        if value is not None:
            setattr(server, field, value)

    db.commit()
    db.refresh(server)
    write_audit(db, admin_user, "server.update", "server", server.name, request=request)
    db.commit()
    return _serialize(db, server)


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: int, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(admin)):
    server = _get_server_or_404(db, server_id)
    name = server.name
    db.query(ServerAssignment).filter(ServerAssignment.server_id == server_id).delete()
    db.delete(server)
    db.commit()
    write_audit(db, admin_user, "server.delete", "server", name, request=request)
    db.commit()


@router.post("/{server_id}/test", response_model=ServerTestResult)
def test_server_endpoint(server_id: int, db: Session = Depends(get_db), user: User = Depends(admin_or_operator)):
    server = _accessible_server(db, user, server_id)
    ok, version, detail, text = test_server(server)
    server.status = "ok" if ok else "error"
    server.version = version or None
    server.last_error = None if ok else detail
    server.last_checked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return ServerTestResult(ok=ok, version=version or None, detail=detail, status_text=text or None)


@router.post("/{server_id}/refresh-status", response_model=ServerOut)
def refresh_status(server_id: int, db: Session = Depends(get_db), user: User = Depends(admin_or_operator)):
    server = _accessible_server(db, user, server_id)
    ok, version, detail, _text = test_server(server)
    server.status = "ok" if ok else "error"
    server.version = version or None
    server.last_error = None if ok else detail
    server.last_checked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return _serialize(db, server)


# --- assignments -------------------------------------------------------------


@router.get("/{server_id}/assignments")
def get_assignments(server_id: int, db: Session = Depends(get_db), user: User = Depends(admin_or_operator)):
    _accessible_server(db, user, server_id)
    rows = db.query(ServerAssignment).filter(ServerAssignment.server_id == server_id).all()
    return {"user_ids": [a.user_id for a in rows]}


@router.put("/{server_id}/assignments")
def set_assignments(
    server_id: int,
    body: ServerAssignmentsIn,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(admin),
):
    server = _get_server_or_404(db, server_id)

    if len(set(body.user_ids)) != len(body.user_ids):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Duplicate user ids")
    for uid in body.user_ids:
        target = db.get(User, uid)
        if target is None or not target.active or target.role != "operator":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"User {uid} is not an active operator")

    db.query(ServerAssignment).filter(ServerAssignment.server_id == server_id).delete()
    for uid in body.user_ids:
        db.add(ServerAssignment(user_id=uid, server_id=server_id))
    db.commit()
    write_audit(db, admin_user, "server.assign", "server", server.name, payload=str(body.user_ids), request=request)
    db.commit()
    return {"user_ids": body.user_ids}


def _get_server_or_404(db: Session, server_id: int) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server