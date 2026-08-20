############################################################################
# Copyright (C) 2016-2018  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.
#
# Adapted from ISC's python-rndc (bin/python/isc/rndc.py, MPL-2.0):
#   - recv replaced with a portable recv_exact loop (no MSG_WAITALL)
#   - per-call connect instead of a persistent session
#   - exceptions normalized to RndcError
############################################################################
import base64
import hashlib
import hmac
import random
import socket
import struct
import time

# Only strong algorithms are accepted. MD5 and SHA-1 are deliberately
# unsupported (HMAC-SHA256/384/512 only).
ALGORITHMS = {
    "sha256": 163,
    "sha384": 164,
    "sha512": 165,
}

_HASHES = {
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

MAX_MESSAGE = 1024 * 1024


class RndcError(Exception):
    """Raised when an rndc exchange fails (auth, protocol, or command error)."""


class RndcClient:
    """Minimal RNDC (isccc) protocol client for controlling BIND9.

    Each call opens a fresh connection: connect, exchange the 'null' nonce
    handshake, issue the command, and close. Stateless and safe to use from
    concurrent request handlers.
    """

    def __init__(self, host: str, port: int, secret_b64: str,
                 algorithm: str = "sha256", timeout: float = 10.0):
        if algorithm not in ALGORITHMS:
            raise RndcError(f"unsupported algorithm: {algorithm}")
        self.host = host
        self.port = port
        self.algorithm = algorithm
        self.hashfn = _HASHES[algorithm]
        self.secret = base64.b64decode(secret_b64)
        self.timeout = timeout
        self._serial = random.randint(0, 1 << 24)

    # --- public API ---------------------------------------------------------

    def call(self, command: str) -> dict:
        """Run a command string (e.g. 'status', 'zonestatus example.com').

        Returns the decoded '_data' mapping of the response. Raises RndcError
        if the server reports an error.
        """
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            self._socket = sock
            try:
                self._login()
                data = self._command({b"type": command.encode()})
            finally:
                self._socket = None
        if b"err" in data:
            raise RndcError(data.get(b"err", b"").decode(errors="replace"))
        return {
            k.decode(errors="replace"): (v.decode(errors="replace") if isinstance(v, bytes) else v)
            for k, v in data.items()
        }

    # --- protocol internals ---------------------------------------------------

    def _login(self) -> None:
        self.nonce = None
        self._command({b"type": b"null"})
        # nonce is captured during _parse_message via _verify
        # (self.nonce set there)

    def _command(self, data: dict) -> dict:
        msg = self._prep_message(data)
        self._send_all(msg)

        header = self._recv_exact(8)
        length, version = struct.unpack(">II", header)
        if version != 1:
            raise RndcError(f"wrong message version {version}")
        if length > MAX_MESSAGE:
            raise RndcError("response too large")
        body = self._recv_exact(length - 4)
        parsed = self._parse_message(body)
        if not self._verify(parsed):
            raise RndcError("authentication failure")
        ctrl = parsed.get(b"_ctrl", {})
        if self.nonce is not None and isinstance(ctrl, dict) and b"_nonce" in ctrl:
            self.nonce = ctrl[b"_nonce"]
        return parsed[b"_data"]

    def _send_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            sent = self._socket.send(view)
            if sent == 0:
                raise RndcError("connection closed while sending")
            view = view[sent:]

    def _recv_exact(self, length: int) -> bytes:
        chunks = []
        remaining = length
        while remaining > 0:
            chunk = self._socket.recv(remaining)
            if not chunk:
                raise RndcError("connection closed while receiving")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _prep_message(self, data: dict) -> bytes:
        self._serial += 1
        now = int(time.time())
        d = {
            b"_ctrl": {
                b"_ser": b"%d" % self._serial,
                b"_tim": b"%d" % now,
                b"_exp": b"%d" % (now + 60),
            },
            b"_data": data,
        }
        if getattr(self, "nonce", None) is not None:
            d[b"_ctrl"][b"_nonce"] = self.nonce

        msg = self._serialize(d, ignore_auth=True)
        digest = hmac.new(self.secret, msg, self.hashfn).digest()
        b64 = base64.b64encode(digest)
        auth = {}
        if self.algorithm == "md5":
            auth[b"hmd5"] = struct.pack("22s", b64)
        else:
            auth[b"hsha"] = struct.pack("B88s", ALGORITHMS[self.algorithm], b64)
        d[b"_auth"] = auth
        msg = self._serialize(d)
        return struct.pack(">II", len(msg) + 4, 1) + msg

    def _verify(self, msg: dict) -> bool:
        auth = msg.get(b"_auth")
        if not isinstance(auth, dict):
            return False
        ctrl = msg.get(b"_ctrl")
        nonce = getattr(self, "nonce", None)
        if nonce is not None and isinstance(ctrl, dict) and b"_nonce" in ctrl:
            if ctrl[b"_nonce"] != nonce:
                return False
        key = b"hmd5" if self.algorithm == "md5" else b"hsha"
        bhash = auth.get(key)
        if not isinstance(bhash, bytes):
            return False
        bhash = bhash + b"=" * (4 - (len(bhash) % 4))
        remote = base64.b64decode(bhash)
        mine = self._serialize(msg, ignore_auth=True)
        return hmac.new(self.secret, mine, self.hashfn).digest() == remote

    def _serialize(self, data: dict, ignore_auth: bool = False) -> bytes:
        rv = b""
        for k, v in data.items():
            if ignore_auth and k == b"_auth":
                continue
            rv += bytes([len(k)]) + k
            if isinstance(v, bytes):
                rv += struct.pack(">BI", 1, len(v)) + v
            elif isinstance(v, dict):
                sd = self._serialize(v)
                rv += struct.pack(">BI", 2, len(sd)) + sd
            else:
                raise RndcError(f"cannot serialize {type(v)}")
        return rv

    def _parse_message(self, data: bytes) -> dict:
        rv = {}
        while data:
            label, value, data = self._parse_element(data)
            rv[label] = value
        return rv

    def _parse_element(self, data: bytes):
        pos = 0
        labellen = data[pos]
        pos += 1
        label = data[pos:pos + labellen]
        pos += labellen
        typ = data[pos]
        pos += 1
        datalen = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        value = data[pos:pos + datalen]
        pos += datalen
        rest = data[pos:]
        if typ == 1:
            return label, value, rest
        elif typ == 2:
            d = {}
            while value:
                ilabel, ivalue, value = self._parse_element(value)
                d[ilabel] = ivalue
            return label, d, rest
        raise RndcError(f"unknown element type {typ}")


# --- convenient command helpers ----------------------------------------------

def parse_status_text(text: str) -> dict:
    """Best-effort parse of `rndc status` output lines into a dict."""
    result = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        result[key.strip()] = value.strip()
    return result