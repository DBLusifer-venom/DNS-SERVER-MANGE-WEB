import pytest


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    # Imported lazily: test modules set env vars at import time, and
    # Settings is cached on first get_settings() call.
    from app.services.ratelimit import reset

    reset()
    yield
    reset()