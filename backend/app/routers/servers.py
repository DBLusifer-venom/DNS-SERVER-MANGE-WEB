from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_role, write_audit
from ..models import Server, User
from ..schemas import ServerCreate, ServerOut, ServerTestResult, ServerUpdate
from ..security import encrypt_secret
from ..services.bind_control import BindServer, test_server

router = APIRouter(prefix="/api/servers", tags=["servers"])
admin = require_role("admin")
admin_or_operator = require_role("admin", "operator")


def _get_server_or_404(db: Session, server_id: int) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server


@router.get("", response_model=list[ServerOut])
def list_servers(db: Session = Depends(get_db), _=Depends(admin_or_operator)):
    return db.query(Server).order_by(Server.name).all()


@router.post("", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
def create_server(body: ServerCreate, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(admin)):
    if db.query(Server).filter(Server.name == body.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Server name already exists")

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
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    write_audit(db, admin_user, "server.create", "server", server.name, request=request)
    db.commit()
    return server


@router.get("/{server_id}", response_model=ServerOut)
def get_server(server_id: int, db: Session = Depends(get_db), _=Depends(admin_or_operator)):
    return _get_server_or_404(db, server_id)


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
    return server


@router.delete("/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: int, request: Request, db: Session = Depends(get_db), admin_user: User = Depends(admin)):
    server = _get_server_or_404(db, server_id)
    name = server.name
    db.delete(server)
    db.commit()
    write_audit(db, admin_user, "server.delete", "server", name, request=request)
    db.commit()


@router.post("/{server_id}/test", response_model=ServerTestResult)
def test_server_endpoint(server_id: int, db: Session = Depends(get_db), _=Depends(admin_or_operator)):
    server = _get_server_or_404(db, server_id)
    ok, version, detail, text = test_server(server)
    server.status = "ok" if ok else "error"
    server.version = version or None
    server.last_error = None if ok else detail
    server.last_checked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return ServerTestResult(ok=ok, version=version or None, detail=detail, status_text=text or None)


@router.post("/{server_id}/refresh-status")
def refresh_status(server_id: int, db: Session = Depends(get_db), _=Depends(admin_or_operator)):
    server = _get_server_or_404(db, server_id)
    ok, version, detail, _text = test_server(server)
    server.status = "ok" if ok else "error"
    server.version = version or None
    server.last_error = None if ok else detail
    server.last_checked_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return ServerOut.model_validate(server)