#!/usr/bin/env python3
"""Run randomized paired baseline vs QKD-simulator handshake trials."""

import argparse
import csv
import random
import re
import subprocess
import sys
import time
from pathlib import Path
from statistics import mean, median, stdev


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "phase8"
LOGS = RESULTS / "comparison_runs"
TARGETS = {
    "baseline": (
        ROOT / "build" / "Release" / "server_auth_phase6_adaptive.exe",
        ROOT / "build" / "Release" / "client_auth_phase6_adaptive.exe",
    ),
    "qkd_simulator": (
        ROOT / "build" / "Release" / "server_auth_phase8_qkd.exe",
        ROOT / "build" / "Release" / "client_auth_phase8_qkd.exe",
    ),
}


def metric(pattern, text):
    match = re.search(pattern, text)
    return float(match.group(1)) if match else ""


def run_trial(condition, block, order):
    stem = f"{block:02d}_{condition}"
    server_exe, client_exe = TARGETS[condition]
    server_log = LOGS / f"{stem}_server.log"
    server_err = LOGS / f"{stem}_server.err"
    client_log = LOGS / f"{stem}_client.log"
    client_err = LOGS / f"{stem}_client.err"
    server_process = None
    client_exit = "runner_error"

    with server_log.open("w", encoding="utf-8") as server_out, \
         server_err.open("w", encoding="utf-8") as server_error:
        try:
            server_process = subprocess.Popen(
                [str(server_exe), "--minimum", "768"], cwd=ROOT,
                stdout=server_out, stderr=server_error,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            time.sleep(0.4)
            completed = subprocess.run(
                [str(client_exe), "--minimum", "768"], cwd=ROOT,
                capture_output=True, text=True, timeout=25,
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
                    server_process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    server_process.kill()
                    server_process.wait(timeout=5)

    client_text = client_log.read_text(encoding="utf-8", errors="replace")
    server_text = server_log.read_text(encoding="utf-8", errors="replace")
    client_profile = re.search(r"Selected (ML-KEM-\d+)", client_text)
    server_ok = "RESULT: REPLAY PROTECTION VERIFIED" in server_text
    client_ok = ("CLIENT TEST COMPLETE" in client_text and
                 (condition == "baseline" or
                  "Server authenticated replay rejection confirmed" in client_text))
    return {
        "block": block,
        "order_in_block": order,
        "condition": condition,
        "selected_profile": client_profile.group(1) if client_profile else "",
        "client_exit_code": client_exit,
        "server_replay_verified": server_ok,
        "client_completion_confirmed": client_ok,
        "trial_success": client_exit == 0 and server_ok and client_ok,
        "handshake_ms": metric(
            r"CLIENT_HELLO send through authenticated session-key ready: ([0-9.]+) ms",
            client_text),
        "client_hkdf_stage_ms": metric(
            r"\[PHASE5_STAGE\] HKDF-SHA-384: ([0-9.]+) ms", client_text),
        "client_provider_lookup_ms": metric(
            r"\[PHASE8_METRIC\] provider_lookup_ms: ([0-9.]+)", client_text),
        "client_qkd_hkdf_combine_ms": metric(
            r"\[PHASE8_METRIC\] qkd_hkdf_combine_ms: ([0-9.]+)", client_text),
        "server_hkdf_stage_ms": metric(
            r"\[PHASE5_STAGE\] HKDF-SHA-384: ([0-9.]+) ms", server_text),
        "server_provider_lookup_ms": metric(
            r"\[PHASE8_METRIC\] provider_lookup_ms: ([0-9.]+)", server_text),
        "server_qkd_hkdf_combine_ms": metric(
            r"\[PHASE8_METRIC\] qkd_hkdf_combine_ms: ([0-9.]+)", server_text),
        "client_log": str(client_log.relative_to(ROOT)),
        "server_log": str(server_log.relative_to(ROOT)),
    }


def write_csv(path, rows, fieldnames):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", type=int, default=20,
                        help="paired blocks; each block runs both conditions")
    parser.add_argument("--seed", type=int, default=20261101)
    args = parser.parse_args()
    if args.pairs < 2:
        parser.error("at least two pairs are required for sample standard deviation")

    LOGS.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    rows = []
    for block in range(1, args.pairs + 1):
        order = ["baseline", "qkd_simulator"]
        rng.shuffle(order)
        for order_index, condition in enumerate(order, start=1):
            row = run_trial(condition, block, order_index)
            rows.append(row)
            print(f"block={block}/{args.pairs} condition={condition} "
                  f"success={row['trial_success']} "
                  f"handshake_ms={row['handshake_ms']}", flush=True)

    sample_path = RESULTS / "comparison_samples.csv"
    summary_path = RESULTS / "comparison_summary.csv"
    write_csv(sample_path, rows, list(rows[0]))
    summary = []
    for condition in ("baseline", "qkd_simulator"):
        group = [row for row in rows if row["condition"] == condition]
        good = [row for row in group if row["trial_success"]]
        values = [row["handshake_ms"] for row in good
                  if isinstance(row["handshake_ms"], float)]
        summary.append({
            "condition": condition,
            "trials": len(group),
            "successful_trials": len(good),
            "selected_profile_counts": ";".join(
                f"{profile}:{sum(r['selected_profile'] == profile for r in group)}"
                for profile in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")),
            "handshake_median_ms": median(values) if values else "",
            "handshake_mean_ms": mean(values) if values else "",
            "handshake_sample_sd_ms": stdev(values) if len(values) > 1 else "",
            "client_hkdf_median_ms": median(
                [r["client_hkdf_stage_ms"] for r in good
                 if isinstance(r["client_hkdf_stage_ms"], float)]) if good else "",
            "provider_lookup_median_ms": median(
                [r["client_provider_lookup_ms"] for r in good
                 if isinstance(r["client_provider_lookup_ms"], float)])
                if condition == "qkd_simulator" and good else "",
            "qkd_hkdf_combine_median_ms": median(
                [r["client_qkd_hkdf_combine_ms"] for r in good
                 if isinstance(r["client_qkd_hkdf_combine_ms"], float)])
                if condition == "qkd_simulator" and good else "",
        })

    write_csv(summary_path, summary, list(summary[0]))
    print(f"samples={sample_path}")
    print(f"summary={summary_path}")
    if any(not row["trial_success"] for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
