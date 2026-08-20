"""DNS server destination policy — prevents the API from being used as a
network connectivity probe (SSRF) and keeps the control plane inside
explicitly approved management networks.

Policy:
  - Host is resolved to all IPs (A and AAAA).
  - Any resolved IP in a denied range (loopback, link-local, multicast,
    metadata, documentation/test networks, unspecified) is rejected.
  - Every resolved IP must fall inside the configured allowlist
    (DNS_MANAGEMENT_NETWORKS).
"""

import ipaddress
import socket

from ..config import get_settings

DENIED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),       # unspecified / "this network"
    ipaddress.ip_network("127.0.0.0/8"),     # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (metadata endpoints)
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (deny unless allowlisted)
    ipaddress.ip_network("::/128"),          # unspecified
    ipaddress.ip_network("::1/128"),         # loopback
    ipaddress.ip_network("fc00::/7"),        # unique-local
    ipaddress.ip_network("fe80::/10"),       # link-local
    ipaddress.ip_network("ff00::/8"),        # multicast
    ipaddress.ip_network("2001:db8::/32"),   # documentation
]


def resolve_host_ips(host: str) -> list[ipaddress.IPAddress]:
    """Resolve a host to IP addresses (handles literals and names)."""
    try:
        ip = ipaddress.ip_address(host)
        return [ip]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"host '{host}' does not resolve") from exc
    ips: list[ipaddress.IPAddress] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ValueError(f"host '{host}' resolved to no usable addresses")
    return ips


def validate_destination(host: str) -> None:
    """Raise ValueError if connecting to host is not permitted by policy."""
    settings = get_settings()
    ips = resolve_host_ips(host)

    # Loopback is denied in production; development machines need it for
    # local testing against mock/stub DNS servers.
    denied = DENIED_NETWORKS
    if settings.environment == "development":
        loopback = {ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")}
        denied = [n for n in DENIED_NETWORKS if n not in loopback]
    for ip in ips:
        if any(ip in net for net in denied):
            raise ValueError(f"destination {ip} is in a denied network ({ip.compressed})")

    allowed = [ipaddress.ip_network(n) for n in settings.management_networks]
    if not allowed:
        raise ValueError("no DNS management networks are configured (DNS_MANAGEMENT_NETWORKS)")
    for ip in ips:
        if not any(ip in net for net in allowed):
            raise ValueError(f"destination {ip.compressed} is not inside allowed management networks")


def pin_destination(host: str) -> list[str]:
    """Validate + resolve host, returning the canonical sorted IP list to
    pin on the Server record (the explicit per-server allowlist)."""
    validate_destination(host)
    return sorted({ip.compressed for ip in resolve_host_ips(host)})


def validate_pinned(host: str, pinned_ips: list[str] | None) -> None:
    """At connect time, re-resolve host and require the current IP set to
    be a subset of the pinned set (anti-DNS-rebinding / silent host change).

    A host may legitimately drop an address family (e.g. AAAA removed), so
    a subset is accepted; any *new* address not pinned at registration is
    rejected and the server record must be updated to re-pin.
    """
    if not pinned_ips:
        return  # legacy rows: fall back to validate_destination only
    current = {ip.compressed for ip in resolve_host_ips(host)}
    if not current <= set(pinned_ips):
        raise ValueError(
            f"host '{host}' now resolves to {sorted(current)} which is not within "
            f"pinned IPs {sorted(pinned_ips)}; re-save the server record to re-pin"
        )