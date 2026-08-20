from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

Role = Literal["admin", "operator", "viewer"]
# HMAC-MD5 and HMAC-SHA1 are deliberately not offered.
RndcAlgorithm = Literal["sha256", "sha384", "sha512"]


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: Role | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=10, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: Role
    active: bool
    created_at: datetime


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    action: str
    resource_type: str
    resource_id: str | None
    payload: str | None
    ip_address: str | None
    created_at: datetime


class ServerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    notes: str | None = None
    rndc_port: int = Field(default=953, ge=1, le=65535)
    rndc_key_name: str = Field(min_length=1, max_length=128)
    rndc_algorithm: RndcAlgorithm = "sha256"
    rndc_secret: str = Field(min_length=8, max_length=512)  # base64 secret
    update_port: int = Field(default=53, ge=1, le=65535)
    update_key_name: str = Field(min_length=1, max_length=128)
    update_secret: str = Field(min_length=8, max_length=512)  # base64 secret


class ServerUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    notes: str | None = None
    rndc_port: int | None = Field(default=None, ge=1, le=65535)
    rndc_key_name: str | None = None
    rndc_algorithm: RndcAlgorithm | None = None
    rndc_secret: str | None = None
    update_port: int | None = Field(default=None, ge=1, le=65535)
    update_key_name: str | None = None
    update_secret: str | None = None


class ServerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    host: str
    notes: str | None
    rndc_port: int
    rndc_key_name: str
    rndc_algorithm: str
    update_port: int
    update_key_name: str
    status: str
    version: str | None
    last_error: str | None
    last_checked_at: datetime | None
    created_at: datetime
    assigned_user_ids: list[int] = []
    pinned_ips: list[str] = []

    @field_validator("pinned_ips", mode="before")
    @classmethod
    def _split_pinned(cls, v):
        if isinstance(v, str):
            return [p for p in v.split(",") if p]
        return v or []


class ServerAssignmentsIn(BaseModel):
    user_ids: list[int] = Field(min_length=0)


class ServerTestResult(BaseModel):
    ok: bool
    version: str | None = None
    detail: str
    status_text: str | None = None