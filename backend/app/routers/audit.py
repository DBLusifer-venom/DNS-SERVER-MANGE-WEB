from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import require_role
from ..models import AuditLog
from ..schemas import AuditOut

router = APIRouter(prefix="/api/audit", tags=["audit"])
require_any = require_role("admin", "operator")


@router.get("", response_model=list[AuditOut])
def list_audit(
    action: str | None = Query(default=None),
    user_id: int | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
    _=Depends(require_any),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if user_id:
        q = q.filter(AuditLog.user_id == user_id)
    return q.order_by(desc(AuditLog.created_at)).limit(limit).all()