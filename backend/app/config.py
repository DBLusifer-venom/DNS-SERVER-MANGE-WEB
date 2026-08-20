import base64
import secrets
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

KNOWN_INSECURE_VALUES = {
    "dev-insecure-secret-key-change-me",
    "ChangeMe_Now_123!",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "SecureDNS Manager"
    environment: Literal["development", "production"] = "development"

    # SQLite (dev/small deploys) or PostgreSQL:
    # postgresql+psycopg://user:pass@host:5432/secure_dns
    database_url: str = "sqlite:///./secure_dns.db"

    # JWT signing secret. Required in production; auto-generated for dev.
    secret_key: str | None = None

    # Fernet key for encrypting stored TSIG secrets. Required in production;
    # auto-generated for dev (wiped secrets on restart — dev only).
    fernet_key: str | None = None

    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 14
    login_attempt_limit: int = 5
    login_lockout_minutes: int = 15

    # Bootstrap admin (created on first startup if no users exist).
    # Password is REQUIRED — startup fails without it.
    admin_username: str = "admin"
    admin_password: str | None = None
    admin_email: str = "admin@example.com"

    # CORS origins for dev (comma-separated). Prod is same-origin via nginx.
    cors_origins: str = "http://localhost:5173"

    # Allowlist of CIDR networks the tool may manage DNS servers in.
    # REQUIRED in production. Dev default allows loopback only.
    dns_management_networks: str = "127.0.0.0/8,::1/128"

    # Refresh-token cookie flags. Secure must be on in production.
    cookie_secure: bool = True
    cookie_name: str = "sd_refresh"

    # Rate limiting (in-process; Redis when HA)
    rate_limit_attempts: int = 5
    rate_limit_window_seconds: int = 300

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def management_networks(self) -> list[str]:
        return [n.strip() for n in self.dns_management_networks.split(",") if n.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    # --- resolved secrets (validated at startup via validate()) ------------

    def effective_secret_key(self) -> str:
        if self.secret_key:
            return self.secret_key
        if self.is_production:
            raise RuntimeError("SECRET_KEY is required in production")
        print("[startup] WARNING: SECRET_KEY not set; generating an ephemeral key for development")
        return secrets.token_urlsafe(64)

    def effective_fernet_key(self) -> str:
        if self.fernet_key:
            return self.fernet_key
        if self.is_production:
            raise RuntimeError("FERNET_KEY is required in production")
        print("[startup] WARNING: FERNET_KEY not set; generating an ephemeral key for development")
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

    def validate(self) -> None:
        """Raise RuntimeError with all misconfigurations listed."""
        errors: list[str] = []

        if self.is_production:
            if not self.dns_management_networks:
                errors.append("DNS_MANAGEMENT_NETWORKS must be set in production (CIDR allowlist of DNS server networks)")

        if not self.secret_key:
            if self.is_production:
                errors.append("SECRET_KEY is required in production")
        elif self.secret_key in KNOWN_INSECURE_VALUES:
            errors.append("SECRET_KEY must not be a known development value")

        if not self.fernet_key:
            if self.is_production:
                errors.append("FERNET_KEY is required in production (generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")")
        elif self.fernet_key in KNOWN_INSECURE_VALUES:
            errors.append("FERNET_KEY must not be a known development value")

        if not self.admin_password:
            errors.append("ADMIN_PASSWORD is required (bootstrap admin is created on first startup)")
        elif self.admin_password in KNOWN_INSECURE_VALUES:
            errors.append("ADMIN_PASSWORD must not be a known development value")

        if self.cookie_secure and self.cors_origins and not self.is_production:
            pass  # dev can force cookie_secure=false explicitly

        if errors:
            raise RuntimeError("Refusing to start with insecure configuration:\n  - " + "\n  - ".join(errors))


@lru_cache
def get_settings() -> Settings:
    return Settings()