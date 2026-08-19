"""Threaded mock rndc server speaking the isccc wire protocol.

Reuses the serialization helpers from app.services.rndc so framing and
HMAC computation are tested on both sides of the wire.
"""

import base64
import hashlib
import hmac
import socket
import struct
import threading
import time

from app.services.rndc import ALGORITHMS, RndcClient

RESPONSES = {
    "status": (
        "version: mock-bind 9.18.30\n"
        "running on mock.example: linux x86_64\n"
        "boot time: Wed Jan 01 00:00:00 2026\n"
        "last configured: Wed Jan 01 00:00:00 2026\n"
        "configuration file: /etc/bind/named.conf\n"
        "zones: 5\n"
        "server is up and running\n"
    ),
    "zonestatus example.com": (
        "zone: example.com\n"
        "kind: master\n"
        "serial: 2026010101\n"
        "dnssec: signed\n"
        "secure: yes\n"
    ),
}


class MockRndcServer:
    def __init__(self, secret_b64: str, algorithm: str = "sha256"):
        self.secret = base64.b64decode(secret_b64)
        self.algorithm = algorithm
        self.hashfn = getattr(hashlib, algorithm)
        self._helper = RndcClient("127.0.0.1", 1, secret_b64, algorithm)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self.nonce = 0

    def close(self):
        self._sock.close()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv_exact(self, conn, length):
        chunks = []
        remaining = length
        while remaining > 0:
            chunk = conn.recv(remaining)
            if not chunk:
                raise ConnectionError("closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _handle(self, conn):
        try:
            while True:
                header = self._recv_exact(conn, 4)
                (length,) = struct.unpack(">I", header)
                body = self._recv_exact(conn, length)
                (version,) = struct.unpack(">I", body[:4])
                if version != 1:
                    return
                msg = self._helper._parse_message(body[4:])
                if not self._helper._verify(msg):
                    return  # auth failure -> drop connection
                self._respond(conn, msg)
        except (ConnectionError, OSError):
            pass
        finally:
            conn.close()

    def _respond(self, conn, request):
        self.nonce += 1
        now = int(time.time())
        ctrl = request[b"_ctrl"]
        data = request[b"_data"]
        cmd = data.get(b"type", b"").decode()
        ser = ctrl.get(b"_ser", b"0")
        req_nonce = ctrl.get(b"_nonce")

        text = RESPONSES.get(cmd, "")
        err = b""
        if cmd not in RESPONSES:
            text = "unknown command"
            err = b"unknown command: '%s'" % cmd.encode()

        d = {
            b"_ctrl": {
                b"_ser": ser,
                b"_tim": b"%d" % now,
                b"_exp": b"%d" % (now + 60),
                b"_nonce": b"%d" % self.nonce,
                b"_rpl": b"1",
                b"_ack": b"1",
            },
            b"_data": {
                b"type": data.get(b"type", b""),
                b"text": text.encode(),
            },
        }
        if err:
            d[b"_data"][b"err"] = err
        msg = self._helper._serialize(d, ignore_auth=True)
        digest = hmac.new(self.secret, msg, self.hashfn).digest()
        b64 = base64.b64encode(digest)
        auth = {}
        if self.algorithm == "md5":
            auth[b"hmd5"] = struct.pack("22s", b64)
        else:
            auth[b"hsha"] = struct.pack("B88s", ALGORITHMS[self.algorithm], b64)
        d[b"_auth"] = auth
        msg = self._helper._serialize(d)
        conn.sendall(struct.pack(">II", len(msg) + 4, 1) + msg)