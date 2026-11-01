#!/usr/bin/env python3
"""Summarize a real emulator report and Phase 7 handshake trial CSVs."""

import argparse
import csv
import json
from pathlib import Path
from statistics import mean, median, stdev


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results" / "phase7"


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=RESULTS / "real_loss_trials_5pct.json")
    parser.add_argument("--output", type=Path, default=RESULTS / "real_loss_5pct_summary.csv")
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    if report["session"].get("simulated"):
        raise SystemExit("Refusing simulated emulator output")
    if not report["session"].get("narrowed"):
        raise SystemExit("Refusing a report without a narrowed traffic filter")
    if report["counters"].get("scoped_seen", 0) < 1 or \
       report["counters"].get("drop_loss", 0) < 1:
        raise SystemExit("No scoped packet loss was confirmed in the report")

    source_groups = [
        ("Adaptive (selected ML-KEM-768)", RESULTS / "real_loss_handshake_samples.csv",
         "handshake_completed"),
        ("Fixed ML-KEM-512", RESULTS / "real_loss_fixed512_samples.csv",
         "client_complete"),
        ("Fixed ML-KEM-768", RESULTS / "real_loss_fixed768_samples.csv",
         "client_complete"),
        ("Fixed ML-KEM-1024", RESULTS / "real_loss_fixed1024_samples.csv",
         "client_complete"),
    ]
    rows = []
    for label, path, completion_column in source_groups:
        trials = read_csv(path)
        samples = [float(row["hello_to_key_ms"]) for row in trials
                   if row["hello_to_key_ms"]]
        successes = [row for row in trials
                     if row["client_exit_code"] == "0" and
                     row[completion_column].lower() == "true" and
                     row["server_replay_rejected"].lower() == "true"]
        if len(samples) < 2:
            raise SystemExit(f"Not enough handshake samples in {path}")
        rows.append({
            "condition": label,
            "trials": len(trials),
            "successful_client_and_server_checks": len(successes),
            "median_handshake_ms": f"{median(samples):.3f}",
            "mean_handshake_ms": f"{mean(samples):.3f}",
            "sample_sd_ms": f"{stdev(samples):.3f}",
            "max_handshake_ms": f"{max(samples):.3f}",
            "trials_over_200ms": sum(value > 200 for value in samples),
            "configured_loss_pct": report["settings"]["loss"],
            "scope_effective_loss_pct": report["metrics"]["effective_loss_pct"],
            "scope_packets_seen": report["counters"]["scoped_seen"],
            "scope_packets_dropped": report["counters"]["drop_loss"],
            "scope_target": report["settings"]["target"],
            "scope_destination": f"{report['settings']['dst_ip']}:{report['settings']['dst_port']}",
        })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(f"{row['condition']}: n={row['trials']} "
              f"success={row['successful_client_and_server_checks']} "
              f"median={row['median_handshake_ms']} ms "
              f"mean={row['mean_handshake_ms']} ms "
              f"sd={row['sample_sd_ms']} ms")
    print(f"scoped packets={report['counters']['scoped_seen']} "
          f"dropped={report['counters']['drop_loss']} "
          f"effective_loss={report['metrics']['effective_loss_pct']}%")
    print(f"summary={args.output}")
    return 0 if all(row["trials"] == row["successful_client_and_server_checks"]
                    for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
