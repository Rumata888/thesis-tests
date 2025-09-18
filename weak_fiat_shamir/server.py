import os
import json
import base64
import socket
import socketserver
import time
from hashlib import sha256
from secrets import randbelow
from typing import Tuple, Optional

from ecpy.curves import Curve, Point
from flag import flag


# Curve params (secp256k1)
curve = Curve.get_curve("secp256k1")
G: Point = curve.generator
q: int = curve.order
FIELD = curve.field

N_BYTES = 32
PT_BYTES = 64


def _i2b32(x: int) -> bytes:
    return int(x % FIELD).to_bytes(N_BYTES, "big")


def _ser_point(P: Point) -> bytes:
    return _i2b32(P.x) + _i2b32(P.y)


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            try:
                self.request.settimeout(600)
            except Exception:
                pass
            start_time = time.monotonic()

            def ensure_deadline():
                if time.monotonic() - start_time > 600:
                    raise TimeoutError("connection processing timed out")

            # Generate per-connection A1 like in the notebook's LocalVerifier
            a1 = randbelow(q - 1) + 1
            A1 = a1 * G

            intro = {
                "message": "Notebook-scheme batched Schnorr verify. Use A1 below.",
                "curve": "secp256k1",
                "A1_x": str(A1.x),
                "A1_y": str(A1.y),
            }
            self.request.sendall((json.dumps(intro) + "\n").encode())

            data = self.request.recv(1 << 20)
            ensure_deadline()
            obj = json.loads(data.decode().strip())

            try:
                A2_x = int(obj.get("A2_x", "0"))
                A2_y = int(obj.get("A2_y", "0"))
                A2 = Point(A2_x, A2_y, curve)
                R1_x = int(obj.get("R1_x", "0"))
                R1_y = int(obj.get("R1_y", "0"))
                R1 = Point(R1_x, R1_y, curve)
                R2_x = int(obj.get("R2_x", "0"))
                R2_y = int(obj.get("R2_y", "0"))
                R2 = Point(R2_x, R2_y, curve)
                s_val = int(obj.get("s", "0")) % q
                msg = obj.get("msg", "")
            except Exception:
                self.request.sendall(b'{"ok":false,"error":"invalid fields"}\n')
                return

            # Verify using the exact notebook scheme
            data_bytes = _ser_point(A1) + _ser_point(R1)
            batch_challenge = int.from_bytes(sha256(data_bytes).digest(), "big") % q
            data_bytes += _ser_point(A2) + _ser_point(R2) + msg.encode("latin-1")
            e = int.from_bytes(sha256(data_bytes).digest(), "big") % q

            lhs = (s_val % q) * G
            rhs = R1 + e * A1 + batch_challenge * (R2 + e * A2)
            ok = lhs == rhs
            ensure_deadline()

            resp = {
                "ok": bool(ok),
            }
            if ok:
                resp["flag"] = flag
            self.request.sendall((json.dumps(resp) + "\n").encode())
        except socket.timeout:
            try:
                self.request.sendall(b'{"ok":false,"error":"timeout"}\n')
            except Exception:
                pass
        except Exception as e:
            try:
                self.request.sendall(
                    (json.dumps({"ok": False, "error": str(e)}) + "\n").encode()
                )
            except Exception:
                pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    if os.environ.get("RUN_SCHNORR_SERVER"):
        host = os.environ.get("CHAL_HOST", "0.0.0.0")
        port = int(os.environ.get("CHAL_PORT", "1337"))
        print(f"Starting Schnorr batching server on {host}:{port} ...")
        with ThreadedTCPServer((host, port), ThreadedTCPRequestHandler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                print("Shutting down server...")
