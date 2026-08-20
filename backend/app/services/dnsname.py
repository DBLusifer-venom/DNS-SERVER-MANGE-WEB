"""Strict DNS name validation shared by control-plane operations.

Zone names and record names must never flow from the API into rndc command
strings without passing through here. We validate DNS syntax (RFC 1035 /
RFC 1123 style labels) instead of attempting to sanitize strings.
"""

import re

LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
MAX_NAME_LENGTH = 253


def validate_dns_name(name: str, field: str = "name") -> str:
    """Validate an absolute or relative DNS name.

    Returns the name normalized (lowercased, trailing dot stripped).
    Raises ValueError with a clear message on invalid input.
    """
    if not isinstance(name, str) or not name:
        raise ValueError(f"{field} must not be empty")
    name = name.strip().rstrip(".")
    if not name:
        raise ValueError(f"{field} is invalid")
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"{field} exceeds {MAX_NAME_LENGTH} characters")
    if name.endswith("-") or name.startswith("-"):
        raise ValueError(f"{field} labels must not start or end with '-'")
    labels = name.split(".")
    if any(not LABEL_RE.match(label) for label in labels):
        raise ValueError(f"{field} contains invalid characters or label syntax")
    return name.lower()


def validate_record_name(owner: str, zone: str) -> str:
    """Validate a record owner name. Must be the zone apex, a subdomain of
    the zone, or '@' (apex shorthand)."""
    owner = owner.strip()
    if owner == "@":
        return zone
    if owner.endswith("."):
        owner = owner[:-1]
    owner = owner.lower()
    if owner == zone:
        return zone
    if owner.endswith("." + zone):
        return owner
    raise ValueError(f"record owner '{owner}' is not inside zone '{zone}'")