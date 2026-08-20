from ..models import Server
from ..security import decrypt_secret
from .destpolicy import validate_destination, validate_pinned
from .dnsname import validate_dns_name
from .rndc import RndcClient, RndcError, parse_status_text


def _pinned(server: Server) -> list[str]:
    return [p for p in (server.pinned_ips or "").split(",") if p]


class BindServer:
    """High-level operations against one BIND9 server via rndc."""

    def __init__(self, server: Server):
        self.server = server
        self._rndc: RndcClient | None = None

    def _client(self) -> RndcClient:
        if self._rndc is None:
            validate_destination(self.server.host)  # defense in depth
            validate_pinned(self.server.host, _pinned(self.server))  # anti-DNS-rebinding
            self._rndc = RndcClient(
                host=self.server.host,
                port=self.server.rndc_port,
                secret_b64=decrypt_secret(self.server.rndc_secret_enc),
                algorithm=self.server.rndc_algorithm,
            )
        return self._rndc

    def status(self) -> dict:
        data = self._client().call("status")
        text = data.get("text", "")
        parsed = parse_status_text(text)
        parsed["_raw"] = text
        return parsed

    def zone_status(self, zone: str) -> dict:
        zone = validate_dns_name(zone, "zone")
        data = self._client().call(f"zonestatus {zone}")
        return parse_status_text(data.get("text", ""))

    def add_zone(self, zone: str, options: str) -> str:
        """Create a zone. options is a named.conf-style block, e.g.
        'type master; file "/var/lib/bind/dynamic/example.com"; allow-update { key "update-key"; };'"""
        zone = validate_dns_name(zone, "zone")
        if not options or ";" not in options:
            raise ValueError("zone options must be a valid named.conf block")
        if "\n" in options or "\r" in options:
            raise ValueError("zone options must be a single line")
        data = self._client().call(f"addzone {zone} {options}")
        return data.get("text", "")

    def del_zone(self, zone: str) -> str:
        zone = validate_dns_name(zone, "zone")
        data = self._client().call(f"delzone -clean {zone}")
        return data.get("text", "")

    def reload(self, zone: str | None = None) -> str:
        if zone is not None:
            zone = validate_dns_name(zone, "zone")
        cmd = f"reload {zone}".strip() if zone else "reload"
        data = self._client().call(cmd)
        return data.get("text", "")

    def reconfig(self) -> str:
        data = self._client().call("reconfig")
        return data.get("text", "")

    def dnssec_status(self, zone: str) -> dict:
        zone = validate_dns_name(zone, "zone")
        data = self._client().call(f"dnssec -status {zone}")
        return parse_status_text(data.get("text", ""))


def test_server(server: Server) -> tuple[bool, str, str, str]:
    """Returns (ok, version, detail, raw_status_text)."""
    try:
        validate_destination(server.host)
        validate_pinned(server.host, _pinned(server))
        client = RndcClient(
            host=server.host,
            port=server.rndc_port,
            secret_b64=decrypt_secret(server.rndc_secret_enc),
            algorithm=server.rndc_algorithm,
        )
        data = client.call("status")
        text = data.get("text", "")
        parsed = parse_status_text(text)
        version = parsed.get("version", "")
        return True, version, "rndc connection OK", text
    except (RndcError, OSError, ValueError) as exc:
        return False, "", f"rndc connection failed: {exc}", ""