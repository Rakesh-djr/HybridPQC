#!/usr/bin/env python3
"""Run repeatable Phase 7 adaptive-handshake network-condition trials."""

import argparse
import csv
import re
import subprocess
import sys
import time
from pathlib import Path
from statistics import mean, median, stdev


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "phase7"
CLIENT = ROOT / "build" / "Release" / "client_auth_phase6_adaptive.exe"
SERVER = ROOT / "build" / "Release" / "server_auth_phase7_backend.exe"
PROXY = ROOT / "experiments" / "phase7_tcp_proxy.py"

SCENARIOS = [
    {"name": "rtt40ms", "proxy": ["--rtt-ms", "40"],
     "client": [], "minimum": "768"},
    {"name": "rtt160ms", "proxy": ["--rtt-ms", "160"],
     "client": [], "minimum": "768"},
    {"name": "bandwidth256_default", "proxy": ["--bandwidth-kbps", "256"],
     "client": [], "minimum": "768"},
    {"name": "bandwidth256_policy", "proxy": ["--bandwidth-kbps", "256"],
     "client": ["--minimum", "512", "--bandwidth-kbps", "256",
                "--objective", "latency"], "minimum": "512"},
    {"name": "bandwidth2048_policy", "proxy": ["--bandwidth-kbps", "2048"],
     "client": ["--minimum", "512", "--bandwidth-kbps", "2048",
                "--objective", "latency"], "minimum": "512"},
    {"name": "bandwidth100000_policy", "proxy": ["--bandwidth-kbps", "100000"],
     "client": ["--minimum", "512", "--bandwidth-kbps", "100000",
                "--objective", "latency"], "minimum": "512"},
]


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_trial(scenario, run_id, proxy_csv):
    stem = f"{scenario['name']}_{run_id}"
    server_log = RESULTS / f"grid_server_{stem}.log"
    server_err = RESULTS / f"grid_server_{stem}.err"
    proxy_log = RESULTS / f"grid_proxy_{stem}.log"
    proxy_err = RESULTS / f"grid_proxy_{stem}.err"
    client_log = RESULTS / f"grid_client_{stem}.log"
    server_process = None
    proxy_process = None

    proxy_args = [sys.executable, str(PROXY), "--seed", str(run_id),
                  "--log-csv", str(proxy_csv), *scenario["proxy"]]
    try:
        with proxy_log.open("w", encoding="utf-8") as proxy_out, \
                proxy_err.open("w", encoding="utf-8") as proxy_error:
            proxy_process = subprocess.Popen(
                proxy_args, cwd=ROOT, stdout=proxy_out, stderr=proxy_error,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(0.35)

        with server_log.open("w", encoding="utf-8") as server_out, \
                server_err.open("w", encoding="utf-8") as server_error:
            server_process = subprocess.Popen(
                [str(SERVER), "--minimum", scenario["minimum"]],
                cwd=ROOT, stdout=server_out, stderr=server_error,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(0.35)

        completed = subprocess.run(
            [str(CLIENT), *scenario["client"]], cwd=ROOT,
            capture_output=True, text=True, timeout=45,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        client_log.write_text(completed.stdout + completed.stderr,
                              encoding="utf-8")
    except (OSError, subprocess.TimeoutExpired) as exc:
        client_log.write_text(f"Experiment runner error: {exc}\n",
                              encoding="utf-8")
        completed = None
    finally:
        if server_process is not None and server_process.poll() is None:
            try:
                server_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                stop_process(server_process)
        stop_process(proxy_process)

    client_text = client_log.read_text(encoding="utf-8", errors="replace")
    server_text = server_log.read_text(encoding="utf-8", errors="replace")
    proxy_text = proxy_log.read_text(encoding="utf-8", errors="replace")
    server_error_text = server_err.read_text(encoding="utf-8", errors="replace")
    proxy_error_text = proxy_err.read_text(encoding="utf-8", errors="replace")
    selected = re.search(r"\[PHASE6_POLICY\] Selected (ML-KEM-\d+)", client_text)
    connect = re.search(r"TCP connect latency: ([0-9.]+) ms", client_text)
    handshake = re.search(
        r"CLIENT_HELLO send through authenticated session-key ready: ([0-9.]+) ms",
        client_text)
    proxy_row = {}
    if proxy_csv.exists():
        with proxy_csv.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source))
            if rows:
                proxy_row = rows[-1]

    return {
        "scenario": scenario["name"],
        "run_id": run_id,
        "rtt_ms": scenario["proxy"][scenario["proxy"].index("--rtt-ms") + 1]
            if "--rtt-ms" in scenario["proxy"] else "0",
        "bandwidth_kbps_per_direction":
            scenario["proxy"][scenario["proxy"].index("--bandwidth-kbps") + 1]
            if "--bandwidth-kbps" in scenario["proxy"] else "0",
        "loss_event_percent": "0",
        "loss_holds": proxy_row.get("loss_holds", ""),
        "proxy_duration_ms": proxy_row.get("duration_ms", ""),
        "selected_profile": selected.group(1) if selected else "",
        "client_exit_code": completed.returncode if completed else "runner_error",
        "client_connect_ms": connect.group(1) if connect else "",
        "hello_to_key_ms": handshake.group(1) if handshake else "",
        "handshake_completed": "PHASE 4.6 CLIENT TEST COMPLETE" in client_text,
        "replay_rejected": "RESULT: REPLAY PROTECTION VERIFIED" in server_text,
        "server_error": server_error_text.strip(),
        "proxy_error": proxy_error_text.strip(),
        "proxy_log": proxy_text.strip().splitlines()[-1] if proxy_text.strip() else "",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be at least one")
    if not CLIENT.exists() or not SERVER.exists():
        parser.error("Build client_auth_phase6_adaptive and server_auth_phase7_backend first")

    RESULTS.mkdir(parents=True, exist_ok=True)
    proxy_csv = RESULTS / "grid_proxy_connections.csv"
    sample_csv = RESULTS / "network_condition_grid_samples.csv"
    summary_csv = RESULTS / "network_condition_grid_summary.csv"
    samples = []

    for scenario in SCENARIOS:
        for run_id in range(1, args.runs + 1):
            row = run_trial(scenario, run_id, proxy_csv)
            samples.append(row)
            print(f"{row['scenario']} run {run_id}: "
                  f"{row['selected_profile'] or 'no profile'}, "
                  f"{row['hello_to_key_ms'] or 'no session key'} ms, "
                  f"replay={row['replay_rejected']}", flush=True)

    with sample_csv.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=samples[0].keys())
        writer.writeheader()
        writer.writerows(samples)

    summaries = []
    for scenario in SCENARIOS:
        group = [row for row in samples if row["scenario"] == scenario["name"]]
        values = [float(row["hello_to_key_ms"]) for row in group
                  if row["hello_to_key_ms"]]
        summaries.append({
            "scenario": scenario["name"],
            "profiles_selected": ",".join(sorted({row["selected_profile"] for row in group
                                                  if row["selected_profile"]})),
            "runs": len(group),
            "mean_handshake_ms": f"{mean(values):.3f}" if values else "",
            "median_handshake_ms": f"{median(values):.3f}" if values else "",
            "sample_sd_ms": f"{stdev(values):.3f}" if len(values) > 1 else "",
            "all_handshakes_completed": all(row["handshake_completed"] for row in group),
            "all_replay_checks_passed": all(row["replay_rejected"] for row in group),
        })
    with summary_csv.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=summaries[0].keys())
        writer.writeheader()
        writer.writerows(summaries)

    print(f"Samples: {sample_csv}")
    print(f"Summary: {summary_csv}")


if __name__ == "__main__":
    main()
