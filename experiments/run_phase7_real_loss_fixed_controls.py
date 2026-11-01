#!/usr/bin/env python3
"""Run fixed ML-KEM profile controls under an already active loss filter."""

import argparse
import csv
import re
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "phase7"
SERVER = ROOT / "build" / "Release" / "server_auth_phase7_backend.exe"
CLIENT_TEMPLATE = ROOT / "build" / "Release" / "client_auth_phase6_{profile}.exe"


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_one(profile, run_id):
    stem = f"real_loss_fixed{profile}_{run_id:02d}"
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
                [str(SERVER), "--minimum", "512"], cwd=ROOT,
                stdout=out, stderr=err,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(0.3)
        completed = subprocess.run(
            [str(CLIENT_TEMPLATE).format(profile=profile)], cwd=ROOT,
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
    handshake = re.search(
        r"CLIENT_HELLO send through authenticated session-key ready: ([0-9.]+) ms",
        ctext)
    return {
        "run_id": run_id,
        "fixed_profile": f"ML-KEM-{profile}",
        "client_exit_code": client_exit,
        "hello_to_key_ms": handshake.group(1) if handshake else "",
        "client_complete": "PHASE 4.6 CLIENT TEST COMPLETE" in ctext,
        "server_replay_rejected": "RESULT: REPLAY PROTECTION VERIFIED" in stext,
        "client_log": str(client_log.relative_to(ROOT)),
        "server_log": str(server_log.relative_to(ROOT)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("512", "768", "1024"), required=True)
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("runs must be at least one")

    rows = []
    for run_id in range(1, args.runs + 1):
        row = run_one(args.profile, run_id)
        rows.append(row)
        success = (row["client_exit_code"] == 0 and row["client_complete"]
                   and row["server_replay_rejected"])
        print(f"profile=ML-KEM-{args.profile} run={run_id}/{args.runs} "
              f"success={success} handshake_ms={row['hello_to_key_ms']}",
              flush=True)

    output_path = RESULTS / f"real_loss_fixed{args.profile}_samples.csv"
    with output_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    return 0 if all(row["client_exit_code"] == 0 and
                     row["client_complete"] and
                     row["server_replay_rejected"] for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
