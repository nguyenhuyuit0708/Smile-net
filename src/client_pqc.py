#!/usr/bin/env python3
"""
Smile-Net TLS 1.3 + PQC Client (Nodes 2-5: 10.0.0.2 - 10.0.0.5)
Executes N TLS 1.3 + PQC exchanges against Node 1 (10.0.0.1:4433) and logs detailed metrics.
"""

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import struct
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


def run_client_sessions(
    server_host: str,
    server_port: int,
    client_node: str,
    client_ip: str,
    mode: str,
    cert_dir: str,
    num_sessions: int,
    start_id: int,
    output_file: str,
):
    mldsa = MLDSA65Auth()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(f"{cert_dir}/ca_classic.crt")
    ctx.check_hostname = True

    if mode == "pqc":
        if not configure_ssl_context_groups(ctx, "X25519MLKEM768"):
            raise RuntimeError("Failed to set PQC client KEM group X25519MLKEM768")
        kem_group = "X25519MLKEM768"
        sig_alg = "ML-DSA-65"
    else:
        if not configure_ssl_context_groups(ctx, "X25519"):
            raise RuntimeError("Failed to set Classic client KEM group X25519")
        kem_group = "X25519"
        sig_alg = "ECDSA-P256"

    results = []
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    for i in range(num_sessions):
        session_id = start_id + i
        t_start = time.perf_counter()
        wall_ts = time.time()

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if client_ip:
            raw_sock.bind((client_ip, 0))

        # 1. TCP 3-way handshake
        t_tcp0 = time.perf_counter()
        raw_sock.connect((server_host, server_port))
        tcp_connect_ms = (time.perf_counter() - t_tcp0) * 1000.0
        local_port = raw_sock.getsockname()[1]

        # 2. TLS 1.3 + PQC Handshake
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=server_host, do_handshake_on_connect=False)
        t_tls0 = time.perf_counter()
        tls_sock.do_handshake()
        tls_handshake_ms = (time.perf_counter() - t_tls0) * 1000.0

        peer_cert_der = tls_sock.getpeercert(binary_form=True)
        cert_der_bytes = len(peer_cert_der) if peer_cert_der else 0
        cipher_info = tls_sock.cipher()
        cipher_name = cipher_info[0] if cipher_info else "TLS_AES_256_GCM_SHA384"

        # 3. Application Exchange + ML-DSA-65 Verification
        req_payload = {
            "session_id": session_id,
            "client_node": client_node,
            "client_ip": client_ip,
            "nonce": secrets.token_hex(16),
            "payload": "PQC-TLS13-BENCHMARK-" + ("A" * 128),
        }
        req_bytes = json.dumps(req_payload).encode("utf-8")

        t_app0 = time.perf_counter()
        send_msg(tls_sock, req_bytes)
        resp_bytes = recv_msg(tls_sock)
        app_rtt_ms = (time.perf_counter() - t_app0) * 1000.0

        resp = json.loads(resp_bytes.decode("utf-8"))

        if mode == "pqc":
            transcript = resp["transcript"].encode("utf-8")
            sig = base64.b64decode(resp["mldsa_sig_b64"])
            pub = base64.b64decode(resp["mldsa_pubkey_b64"])
            valid_sig, verify_ms = mldsa.verify(transcript, sig, pub)
            if not valid_sig:
                raise RuntimeError(f"ML-DSA-65 signature verification failed at session {session_id}")
        else:
            verify_ms = 0.0
            valid_sig = True

        tls_sock.close()
        total_session_ms = (time.perf_counter() - t_start) * 1000.0
        time.sleep(0.002)

        record = {
            "session_id": session_id,
            "timestamp": wall_ts,
            "client_node": client_node,
            "client_ip": client_ip,
            "client_port": local_port,
            "server_ip": server_host,
            "server_port": server_port,
            "mode": mode,
            "tls_version": "TLSv1.3",
            "cipher_suite": cipher_name,
            "kem_group": kem_group,
            "sig_alg": sig_alg,
            "cert_der_bytes": cert_der_bytes,
            "tcp_connect_ms": round(tcp_connect_ms, 4),
            "tls_handshake_ms": round(tls_handshake_ms, 4),
            "pqc_sign_ms": resp.get("pqc_sign_ms", 0.0),
            "pqc_verify_ms": round(verify_ms, 4),
            "app_rtt_ms": round(app_rtt_ms, 4),
            "total_session_ms": round(total_session_ms, 4),
            "app_tx_bytes": len(req_bytes) + 4,
            "app_rx_bytes": len(resp_bytes) + 4,
            "sig_verified": valid_sig,
        }
        results.append(record)

    with open(output_file, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    print(
        f"[{client_node} ({client_ip})] Completed {num_sessions} {mode.upper()} sessions "
        f"(IDs {start_id}..{start_id + num_sessions - 1}) -> {output_file}",
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-host", default="10.0.0.1")
    parser.add_argument("--server-port", type=int, default=4433)
    parser.add_argument("--client-node", required=True)
    parser.add_argument("--client-ip", default="")
    parser.add_argument("--mode", choices=["pqc", "classic"], default="pqc")
    parser.add_argument("--cert-dir", default="/mnt/f/Smile-Net/certs")
    parser.add_argument("--num-sessions", type=int, default=250)
    parser.add_argument("--start-id", type=int, default=1)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run_client_sessions(
        args.server_host,
        args.server_port,
        args.client_node,
        args.client_ip,
        args.mode,
        args.cert_dir,
        args.num_sessions,
        args.start_id,
        args.output,
    )
