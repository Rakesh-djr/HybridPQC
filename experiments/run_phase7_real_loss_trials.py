#!/usr/bin/env python3
"""Run repeated project handshakes while an external packet-loss filter is active.

Start the Windows emulator separately, scoped to the persistent project proxy
PID, loopback, and backend port 5556. This runner does not claim an impairment;
the emulator's final report supplies the authoritative packet-drop counters.
"""

import argparse
import csv
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "phase7"
CLIENT = ROOT / "build" / "Release" / "client_auth_phase6_adaptive.exe"
SERVER = ROOT / "build" / "Release" / "server_auth_phase7_backend.exe"


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_one(run_id):
    stem = f"real_loss_{run_id:02d}"
    server_log = RESULTS / f"{stem}_server.log"
    server_err = RESULTS / f"{stem}_server.err"
    client_log = RESULTS / f"{stem}_client.log"
    client_err = RESULTS / f"{stem}_client.err"
    server_process = None
    client_exit = "runner_error"
    try:
        with server_log.open("w", encoding="utf-8") as out, \
             server_err.open("w", encoding="utf-8") as err:
            server_process = subprocess.Popen(
                [str(SERVER), "--minimum", "768"], cwd=ROOT,
                stdout=out, stderr=err,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(0.3)
        completed = subprocess.run(
            [str(CLIENT), "--minimum", "768"], cwd=ROOT,
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        client_exit = completed.returncode
        client_log.write_text(completed.stdout, encoding="utf-8")
        client_err.write_text(completed.stderr, encoding="utf-8")
    except (OSError, subprocess.TimeoutExpired) as exc:
        client_log.write_text(f"Experiment runner error: {exc}\n",
                              encoding="utf-8")
        client_err.write_text("", encoding="utf-8")
    finally:
        if server_process is not None and server_process.poll() is None:
            try:
                server_process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                stop_process(server_process)

    ctext = client_log.read_text(encoding="utf-8", errors="replace")
    stext = server_log.read_text(encoding="utf-8", errors="replace")
    selected = re.search(r"Selected (ML-KEM-\d+)", ctext)
    connect = re.search(r"TCP connect latency: ([0-9.]+) ms", ctext)
    handshake = re.search(
        r"CLIENT_HELLO send through authenticated session-key ready: ([0-9.]+) ms",
        ctext)
    return {
        "run_id": run_id,
        "selected_profile": selected.group(1) if selected else "",
        "client_exit_code": client_exit,
        "client_connect_ms": connect.group(1) if connect else "",
        "hello_to_key_ms": handshake.group(1) if handshake else "",
        "handshake_completed": "PHASE 4.6 CLIENT TEST COMPLETE" in ctext,
        "server_replay_rejected": "RESULT: REPLAY PROTECTION VERIFIED" in stext,
        "loss_percentage": "see emulator aggregate report",
        "client_log": str(client_log.relative_to(ROOT)),
        "server_log": str(server_log.relative_to(ROOT)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--first-run-id", type=int, default=1)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be at least one")

    rows = []
    for run_id in range(args.first_run_id,
                        args.first_run_id + args.runs):
        row = run_one(run_id)
        rows.append(row)
        print(f"run={run_id} profile={row['selected_profile']} "
              f"success={row['client_exit_code'] == 0 and row['handshake_completed'] and row['server_replay_rejected']} "
              f"handshake_ms={row['hello_to_key_ms']}", flush=True)

    output_path = RESULTS / "real_loss_handshake_samples.csv"
    write_header = not output_path.exists()
    with output_path.open("a", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        if write_header:
            writer.writeheader()
        writer.writerows(rows)
    return 0 if all(row["client_exit_code"] == 0 and
                     row["handshake_completed"] and
                     row["server_replay_rejected"] for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
