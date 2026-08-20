from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import Settings, get_settings
from .database import Base, SessionLocal, engine
from .models import User
from .routers import audit, auth, servers, users
from .security import hash_password

settings = get_settings()


def create_app(settings_override: Settings | None = None) -> FastAPI:
    cfg = settings_override or settings
    docs_url: str | None = "/docs" if not cfg.is_production else None
    redoc_url: str | None = "/redoc" if not cfg.is_production else None
    openapi_url: str | None = "/openapi.json" if not cfg.is_production else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        cfg.validate()
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            if db.query(User).count() == 0:
                db.add(
                    User(
                        username=cfg.admin_username,
                        email=cfg.admin_email,
                        password_hash=hash_password(cfg.admin_password),
                        role="admin",
                    )
                )
                db.commit()
                print(f"[startup] Created bootstrap admin user: {cfg.admin_username}")
        finally:
            db.close()
        yield

    app = FastAPI(title=cfg.app_name, version="0.1.0", lifespan=lifespan,
                  docs_url=docs_url, redoc_url=redoc_url, openapi_url=openapi_url)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(servers.router)
    app.include_router(audit.router)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "app": cfg.app_name}

    return app


app = create_app()