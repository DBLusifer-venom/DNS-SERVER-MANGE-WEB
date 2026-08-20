import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["DATABASE_URL"] = "sqlite:///./test_secure_dns.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["FERNET_KEY"] = base64.urlsafe_b64encode(b"f" * 32).decode()
os.environ["ADMIN_PASSWORD"] = "Test_Admin_Pass_123!"
os.environ["ADMIN_USERNAME"] = "tadmin"
os.environ["COOKIE_SECURE"] = "false"

import pytest

from app.config import Settings
from app.main import create_app
from app.services import destpolicy


def prod_settings(**overrides) -> Settings:
    base = dict(
        environment="production",
        secret_key=os.environ["SECRET_KEY"],
        fernet_key=os.environ["FERNET_KEY"],
        admin_password=os.environ["ADMIN_PASSWORD"],
        dns_management_networks="10.0.0.0/8",
        cookie_secure=True,
    )
    base.update(overrides)
    return Settings(**base)


class TestStartupValidation:
    def test_production_refuses_missing_secret_key(self):
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            prod_settings(secret_key=None).validate()

    def test_production_refuses_missing_fernet_key(self):
        with pytest.raises(RuntimeError, match="FERNET_KEY"):
            prod_settings(fernet_key=None).validate()

    def test_production_refuses_missing_admin_password(self):
        with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
            prod_settings(admin_password=None).validate()

    def test_production_refuses_known_insecure_values(self):
        with pytest.raises(RuntimeError, match="known development value"):
            prod_settings(secret_key="dev-insecure-secret-key-change-me").validate()
        with pytest.raises(RuntimeError, match="known development value"):
            prod_settings(admin_password="ChangeMe_Now_123!").validate()

    def test_production_refuses_missing_networks(self):
        with pytest.raises(RuntimeError, match="DNS_MANAGEMENT_NETWORKS"):
            prod_settings(dns_management_networks="").validate()

    def test_production_valid_config_passes(self):
        prod_settings().validate()  # must not raise

    def test_development_allows_ephemeral_secrets(self):
        dev = Settings(environment="development")
        assert dev.effective_secret_key()
        assert dev.effective_fernet_key()
        dev.validate()  # no error: dev auto-generates keys

    def test_lists_all_errors(self):
        with pytest.raises(RuntimeError) as exc:
            prod_settings(secret_key=None, fernet_key=None, admin_password=None, dns_management_networks="").validate()
        for part in ("SECRET_KEY", "FERNET_KEY", "ADMIN_PASSWORD", "DNS_MANAGEMENT_NETWORKS"):
            assert part in str(exc.value)


class TestDocsDisabledInProduction:
    @staticmethod
    def _paths(app):
        return {getattr(r, "path", None) for r in app.routes}

    def test_production_has_no_docs(self):
        app = create_app(prod_settings())
        paths = self._paths(app)
        assert "/docs" not in paths
        assert "/redoc" not in paths
        assert "/openapi.json" not in paths

    def test_development_has_docs(self):
        app = create_app(Settings(environment="development"))
        paths = self._paths(app)
        assert "/docs" in paths


class TestDestinationPolicy:
    def test_loopback_allowed_in_dev(self):
        destpolicy.validate_destination("127.0.0.1")  # dev allowlist permits it

    def test_link_local_denied(self):
        with pytest.raises(ValueError, match="denied network"):
            destpolicy.validate_destination("169.254.169.254")

    def test_multicast_denied(self):
        with pytest.raises(ValueError, match="denied network"):
            destpolicy.validate_destination("224.0.0.1")

    def test_private_outside_allowlist_denied(self):
        with pytest.raises(ValueError, match="not inside allowed"):
            destpolicy.validate_destination("10.1.2.3")

    def test_ipv6_loopback_denied_in_production(self, monkeypatch):
        monkeypatch.setattr(destpolicy, "get_settings", lambda: prod_settings())
        with pytest.raises(ValueError, match="denied network"):
            destpolicy.validate_destination("::1")

    def test_private_inside_custom_allowlist_ok(self, monkeypatch):
        monkeypatch.setattr(destpolicy, "get_settings", lambda: prod_settings())
        destpolicy.validate_destination("10.2.3.4")  # 10.0.0.0/8 allowlist

    def test_bad_hostname_rejected(self):
        with pytest.raises(ValueError):
            destpolicy.validate_destination("no-such-host.invalid.")

    def test_pin_destination_returns_canonical_ips(self):
        assert destpolicy.pin_destination("127.0.0.1") == ["127.0.0.1"]

    def test_validate_pinned_accepts_current_subset(self):
        destpolicy.validate_pinned("127.0.0.1", ["127.0.0.1"])

    def test_validate_pinned_rejects_new_ip(self):
        with pytest.raises(ValueError, match="re-pin"):
            destpolicy.validate_pinned("127.0.0.1", ["127.0.0.2"])

    def test_validate_pinned_noop_without_pins(self):
        destpolicy.validate_pinned("127.0.0.1", None)  # legacy rows
        destpolicy.validate_pinned("127.0.0.1", [])