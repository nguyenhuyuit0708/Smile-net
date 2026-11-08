#!/usr/bin/env python3
"""
Smile-Net 5-Node Mininet Topology & 1000-Session PQC TLS 1.3 Experiment Runner.

Topology:
  Switch: s1 (LinuxBridge)
  Node 1: srv      (10.0.0.1/24) - PQC TLS 1.3 Server
  Node 2: client_1 (10.0.0.2/24) - PQC TLS 1.3 Client (250 sessions)
  Node 3: client_2 (10.0.0.3/24) - PQC TLS 1.3 Client (250 sessions)
  Node 4: client_3 (10.0.0.4/24) - PQC TLS 1.3 Client (250 sessions)
  Node 5: client_4 (10.0.0.5/24) - PQC TLS 1.3 Client (250 sessions)
  Total : 1000 PQC TLS 1.3 exchanges + 200 Classical TLS 1.3 baseline exchanges.
"""

import json
import os
import shutil
import signal
import subprocess
import time
from mininet.net import Mininet
from mininet.nodelib import LinuxBridge
from mininet.log import setLogLevel, info

BASE_DIR = "/mnt/f/Smile-Net"
SRC_DIR = f"{BASE_DIR}/src"
CERT_DIR = f"{BASE_DIR}/certs"
CAP_DIR = f"{BASE_DIR}/captures"
DATA_DIR = f"{BASE_DIR}/data"
CONF_FILE = f"{BASE_DIR}/config/openssl_pqc.cnf"


def configure_interface_qos(node, iface: str, delay_ms: str = "2.0ms", jitter_ms: str = "0.4ms", rate: str = "100mbit"):
    """Disable TSO/GSO/GRO for accurate MTU-1500 packet capture and apply netem delay/rate."""
    node.cmd(f"ip link set dev {iface} mtu 1500")
    node.cmd(f"ethtool -K {iface} tso off gso off gro off tx off rx off 2>/dev/null || true")
    node.cmd(f"tc qdisc del dev {iface} root 2>/dev/null || true")
    node.cmd(f"tc qdisc add dev {iface} root netem delay {delay_ms} {jitter_ms} distribution normal rate {rate}")


def run_simulation():
    os.makedirs(CAP_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Clean up any stale Mininet state
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    info("=== [1/6] Building 5-Node Mininet Topology (1 Server + 4 Clients) ===\n")
    net = Mininet(switch=LinuxBridge, controller=None)

    s1 = net.addSwitch("s1")
    srv = net.addHost("srv", ip="10.0.0.1/24")
    c1 = net.addHost("client_1", ip="10.0.0.2/24")
    c2 = net.addHost("client_2", ip="10.0.0.3/24")
    c3 = net.addHost("client_3", ip="10.0.0.4/24")
    c4 = net.addHost("client_4", ip="10.0.0.5/24")

    clients = [
        ("client_1", c1, "10.0.0.2"),
        ("client_2", c2, "10.0.0.3"),
        ("client_3", c3, "10.0.0.4"),
        ("client_4", c4, "10.0.0.5"),
    ]

    net.addLink(srv, s1)
    for _, c_node, _ in clients:
        net.addLink(c_node, s1)

    net.start()

    try:
        info("=== [2/6] Configuring Link MTU (1500), Disabling TSO/GSO, Setting Netem Delay/Rate ===\n")
        configure_interface_qos(srv, "srv-eth0", delay_ms="2.0ms", jitter_ms="0.4ms", rate="100mbit")
        for idx, (c_name, c_node, _) in enumerate(clients, start=1):
            # Slight per-node link delay variation (1.8ms - 2.7ms) to reflect realistic physical distances
            d_ms = f"{1.5 + idx * 0.3:.1f}ms"
            configure_interface_qos(c_node, f"{c_name}-eth0", delay_ms=d_ms, jitter_ms="0.3ms", rate="100mbit")

        # Disable TSO/GSO on switch ports as well
        for port_idx in range(1, 6):
            s1.cmd(f"ethtool -K s1-eth{port_idx} tso off gso off gro off 2>/dev/null || true")

        info("=== [3/6] Testing Connectivity Across All 5 Nodes (pingAll) ===\n")
        loss = net.pingAll(timeout="1")
        if loss > 0:
            raise RuntimeError(f"Network connectivity check failed with {loss}% packet loss")

        # -------------------------------------------------------------------------
        # PART A: 1000 PQC TLS 1.3 Exchanges (X25519MLKEM768 + ML-DSA-65)
        # -------------------------------------------------------------------------
        tmp_pcap_pqc = "/tmp/tls_pqc_1000.pcap"
        pcap_pqc = f"{CAP_DIR}/tls_pqc_1000.pcap"
        srv.cmd(f"rm -f {tmp_pcap_pqc} {pcap_pqc}")

        info("=== [4/6] Starting PQC TLS 1.3 Server & tcpdump on Node 1 (srv: 10.0.0.1:4433) ===\n")
        tcpdump_pqc = srv.popen(
            ["tcpdump", "-i", "srv-eth0", "-B", "65536", "-s", "0", "-n", "-w", tmp_pcap_pqc, "tcp port 4433"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.2)

        env_vars = os.environ.copy()
        env_vars["OPENSSL_CONF"] = CONF_FILE

        srv_pqc_proc = srv.popen(
            [
                "python3",
                f"{SRC_DIR}/server_pqc.py",
                "--host",
                "10.0.0.1",
                "--port",
                "4433",
                "--mode",
                "pqc",
                "--cert-dir",
                CERT_DIR,
            ],
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.5)

        info("=== [5/6] Executing 1000 TLS 1.3 + PQC Exchanges Across 4 Client Nodes (250 each) ===\n")
        t_pqc_start = time.time()
        client_procs = []
        for idx, (c_name, c_node, c_ip) in enumerate(clients):
            start_id = idx * 250 + 1
            out_jsonl = f"{DATA_DIR}/pqc_{c_name}.jsonl"
            p = c_node.popen(
                [
                    "python3",
                    f"{SRC_DIR}/client_pqc.py",
                    "--server-host",
                    "10.0.0.1",
                    "--server-port",
                    "4433",
                    "--client-node",
                    c_name,
                    "--client-ip",
                    c_ip,
                    "--mode",
                    "pqc",
                    "--cert-dir",
                    CERT_DIR,
                    "--num-sessions",
                    "250",
                    "--start-id",
                    str(start_id),
                    "--output",
                    out_jsonl,
                ],
                env=env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            client_procs.append((c_name, p, out_jsonl))

        for c_name, p, _ in client_procs:
            out, err = p.communicate()
            if p.returncode != 0:
                raise RuntimeError(f"Client {c_name} failed: {err.decode('utf-8', errors='replace')}")
            info(f"  -> {out.decode('utf-8').strip()}\n")

        t_pqc_Duration = time.time() - t_pqc_start
        info(f"  [OK] 1000 PQC TLS 1.3 exchanges completed in {t_pqc_Duration:.2f}s!\n")

        time.sleep(1.5)
        srv_pqc_proc.terminate()
        tcpdump_pqc.send_signal(signal.SIGINT)
        _, td_err = tcpdump_pqc.communicate()
        info(f"  [tcpdump PQC] {td_err.decode('utf-8', errors='replace').strip()}\n")
        shutil.copyfile(tmp_pcap_pqc, pcap_pqc)

        # Merge all 1000 session logs
        all_pqc_records = []
        for _, _, out_jsonl in client_procs:
            with open(out_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        all_pqc_records.append(json.loads(line))
        all_pqc_records.sort(key=lambda x: x["session_id"])

        merged_pqc_path = f"{DATA_DIR}/sessions_pqc_1000.json"
        with open(merged_pqc_path, "w", encoding="utf-8") as f:
            json.dump(all_pqc_records, f, indent=2)

        # -------------------------------------------------------------------------
        # PART B: Classical TLS 1.3 Baseline (200 sessions across 4 clients, 50 each)
        # -------------------------------------------------------------------------
        info("=== [6/6] Running Classical TLS 1.3 Baseline (X25519 + ECDSA-P256) on Port 4434 ===\n")
        tmp_pcap_classic = "/tmp/tls_classic_baseline.pcap"
        pcap_classic = f"{CAP_DIR}/tls_classic_baseline.pcap"
        srv.cmd(f"rm -f {tmp_pcap_classic} {pcap_classic}")

        tcpdump_classic = srv.popen(
            ["tcpdump", "-i", "srv-eth0", "-B", "65536", "-s", "0", "-n", "-w", tmp_pcap_classic, "tcp port 4434"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.0)

        srv_classic_proc = srv.popen(
            [
                "python3",
                f"{SRC_DIR}/server_pqc.py",
                "--host",
                "10.0.0.1",
                "--port",
                "4434",
                "--mode",
                "classic",
                "--cert-dir",
                CERT_DIR,
            ],
            env=env_vars,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1.0)

        classic_procs = []
        for idx, (c_name, c_node, c_ip) in enumerate(clients):
            start_id = idx * 50 + 1
            out_jsonl = f"{DATA_DIR}/classic_{c_name}.jsonl"
            p = c_node.popen(
                [
                    "python3",
                    f"{SRC_DIR}/client_pqc.py",
                    "--server-host",
                    "10.0.0.1",
                    "--server-port",
                    "4434",
                    "--client-node",
                    c_name,
                    "--client-ip",
                    c_ip,
                    "--mode",
                    "classic",
                    "--cert-dir",
                    CERT_DIR,
                    "--num-sessions",
                    "50",
                    "--start-id",
                    str(start_id),
                    "--output",
                    out_jsonl,
                ],
                env=env_vars,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            classic_procs.append((c_name, p, out_jsonl))

        for c_name, p, _ in classic_procs:
            out, err = p.communicate()
            if p.returncode != 0:
                raise RuntimeError(f"Classic Client {c_name} failed: {err.decode('utf-8', errors='replace')}")
            info(f"  -> {out.decode('utf-8').strip()}\n")

        time.sleep(1.2)
        srv_classic_proc.terminate()
        tcpdump_classic.send_signal(signal.SIGINT)
        _, td_cls_err = tcpdump_classic.communicate()
        info(f"  [tcpdump Classic] {td_cls_err.decode('utf-8', errors='replace').strip()}\n")
        shutil.copyfile(tmp_pcap_classic, pcap_classic)

        all_classic_records = []
        for _, _, out_jsonl in classic_procs:
            with open(out_jsonl, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        all_classic_records.append(json.loads(line))
        all_classic_records.sort(key=lambda x: x["session_id"])

        merged_classic_path = f"{DATA_DIR}/sessions_classic_200.json"
        with open(merged_classic_path, "w", encoding="utf-8") as f:
            json.dump(all_classic_records, f, indent=2)

        info("=== Simulation & Packet Capture Completed Successfully! ===\n")

    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_simulation()
