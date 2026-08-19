import base64
import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "SecureDNS Manager"
    debug: bool = False

    # SQLite (dev/small deploys) or PostgreSQL:
    # postgresql+psycopg://user:pass@host:5432/secure_dns
    database_url: str = "sqlite:///./secure_dns.db"

    # JWT signing secret. MUST be overridden in production (generate with:
    # python -c "import secrets; print(secrets.token_urlsafe(64))")
    secret_key: str = "dev-insecure-secret-key-change-me"

    # Fernet key for encrypting stored API keys. Auto-generated for dev if empty.
    fernet_key: str = ""

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    login_attempt_limit: int = 5
    login_lockout_minutes: int = 15

    # Bootstrap admin (created on first startup if no users exist)
    admin_username: str = "admin"
    admin_password: str = "ChangeMe_Now_123!"
    admin_email: str = "admin@example.com"

    # CORS origins for dev (comma-separated). Prod is same-origin via nginx.
    cors_origins: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def resolved_fernet_key(self) -> str:
        if self.fernet_key:
            return self.fernet_key
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


@lru_cache
def get_settings() -> Settings:
    return Settings()