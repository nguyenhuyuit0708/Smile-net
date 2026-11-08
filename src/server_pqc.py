#!/usr/bin/env python3
"""
Smile-Net TLS 1.3 + PQC Server (Node 1: 10.0.0.1:4433)
Supports:
- PQC Mode: TLS 1.3 with X25519MLKEM768 (IANA 0x11EC) + Catalyst ML-DSA-65 X.509 Cert + ML-DSA-65 transcript signature
- Classic Mode: TLS 1.3 with X25519 + ECDSA P-256 X.509 Cert
"""

import argparse
import base64
import json
import socket
import ssl
import struct
import threading
import time
from pqc_crypto import MLDSA65Auth, configure_ssl_context_groups


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed during recv_exact")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock: socket.socket, payload: bytes):
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_msg(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    (length,) = struct.unpack("!I", hdr)
    return recv_exact(sock, length)


class PQCTLSServer:
    def __init__(self, host: str, port: int, mode: str, cert_dir: str):
        self.host = host
        self.port = port
        self.mode = mode
        self.cert_dir = cert_dir
        self.mldsa = MLDSA65Auth()
        self.pubkey, self.seckey = self.mldsa.generate_keypair()
        self.pubkey_b64 = base64.b64encode(self.pubkey).decode("ascii")

        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # Disable session tickets so every one of the 1000 sessions performs a full PQC KEM handshake
        self.ctx.options |= ssl.OP_NO_TICKET

        if mode == "pqc":
            if not configure_ssl_context_groups(self.ctx, "X25519MLKEM768:mlkem768"):
                raise RuntimeError("Failed to set PQC KEM groups X25519MLKEM768:mlkem768")
            self.ctx.load_cert_chain(
                f"{cert_dir}/server_hybrid_pqc.crt",
                f"{cert_dir}/server_classic.key",
            )
            self.kem_name = "X25519MLKEM768"
            self.sig_name = "ML-DSA-65"
        else:
            if not configure_ssl_context_groups(self.ctx, "X25519:P-256"):
                raise RuntimeError("Failed to set Classic KEM groups X25519:P-256")
            self.ctx.load_cert_chain(
                f"{cert_dir}/server_classic.crt",
                f"{cert_dir}/server_classic.key",
            )
            self.kem_name = "X25519"
            self.sig_name = "ECDSA-P256"

    def handle_client(self, conn: socket.socket, addr):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.ctx.wrap_socket(conn, server_side=True) as tls_conn:
                req_bytes = recv_msg(tls_conn)
                req = json.loads(req_bytes.decode("utf-8"))

                transcript = f"{req.get('session_id')}:{req.get('client_node')}:{req.get('nonce')}:{self.kem_name}".encode("utf-8")
                if self.mode == "pqc":
                    sig, sign_ms = self.mldsa.sign(transcript)
                    sig_b64 = base64.b64encode(sig).decode("ascii")
                    pub_b64 = self.pubkey_b64
                else:
                    sig_b64 = ""
                    pub_b64 = ""
                    sign_ms = 0.0

                resp = {
                    "status": "OK",
                    "session_id": req.get("session_id"),
                    "server_node": "srv (10.0.0.1)",
                    "mode": self.mode,
                    "kem_group": self.kem_name,
                    "sig_alg": self.sig_name,
                    "pqc_sign_ms": round(sign_ms, 4),
                    "transcript": transcript.decode("utf-8"),
                    "mldsa_pubkey_b64": pub_b64,
                    "mldsa_sig_b64": sig_b64,
                    "server_ts": time.time(),
                }
                send_msg(tls_conn, json.dumps(resp).encode("utf-8"))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind((self.host, self.port))
            srv_sock.listen(512)
            print(
                f"[Server] Listening on {self.host}:{self.port} | Mode={self.mode.upper()} "
                f"| KEM={self.kem_name} | Auth={self.sig_name}",
                flush=True,
            )
            while True:
                conn, addr = srv_sock.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                t.start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="10.0.0.1")
    parser.add_argument("--port", type=int, default=4433)
    parser.add_argument("--mode", choices=["pqc", "classic"], default="pqc")
    parser.add_argument("--cert-dir", default="/mnt/f/Smile-Net/certs")
    args = parser.parse_args()

    server = PQCTLSServer(args.host, args.port, args.mode, args.cert_dir)
    server.serve_forever()

