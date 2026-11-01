# Phase 7: Network-condition experiments

## What this experiment measures

The adaptive ML-KEM-768 handshake was run through a local TCP forwarding proxy. The proxy can add round-trip delay, pace bytes independently in each direction, or hold intact byte chunks for a configured recovery interval. Every condition used three runs. The handshake timer is the client's existing `CLIENT_HELLO` send-to-session-key interval; proxy duration includes later encrypted application and replay-protection traffic, so the two durations are not interchangeable.

| Condition | Selected profile | Median handshake | Mean ± sample SD | Handshakes / replay checks |
|---|---|---:|---:|---|
| Baseline proxy | ML-KEM-768 | 13.339 ms | 13.913 ± 1.799 ms | 3 / 3 passed |
| 80 ms configured RTT | ML-KEM-768 | 114.508 ms | 114.973 ± 2.947 ms | 3 / 3 passed |
| 512 kbps per direction, default policy | ML-KEM-768 | 173.468 ms | 176.439 ± 54.843 ms | 3 / 3 passed |
| 512 kbps per direction, policy given 512 kbps | ML-KEM-512 | 108.360 ms | 106.621 ± 4.029 ms | 3 / 3 passed |
| 100 ms hold on every forwarded chunk | ML-KEM-768 | 228.705 ms | 225.238 ± 6.227 ms | 3 / 3 passed |

The two bandwidth-limited cases show the policy using the bandwidth input to select the smaller ML-KEM-512 hello. Its observed median was about 37.5% lower than the three ML-KEM-768 trials under the same proxy limit. The 768 trials had substantial spread, so treat this as pilot evidence and repeat with more runs before drawing a firm performance conclusion.

## How to reproduce

Start the backend server in one terminal:

```powershell
.\build\Release\server_auth_phase7_backend.exe --minimum 512
```

Start the proxy in another terminal. Use `--rtt-ms 80`, `--bandwidth-kbps 512`, or both to select a condition:

```powershell
python .\experiments\phase7_tcp_proxy.py --bandwidth-kbps 512 --log-csv .\results\phase7\proxy_connections.csv
```

Then run the adaptive client with the same bandwidth estimate and a minimum that permits ML-KEM-512:

```powershell
.\build\Release\client_auth_phase6_adaptive.exe --minimum 512 --bandwidth-kbps 512 --objective latency
```

The proxy binds to port 5555, where the client connects, and forwards to the backend on port 5556. The proxy records flow bytes and its applied condition. The raw handshake and proxy observations are in [`network_condition_samples.csv`](network_condition_samples.csv), with aggregates in [`network_condition_summary.csv`](network_condition_summary.csv).

## Packet-loss experiment

The proxy's **loss-like hold** condition still delays an intact stream chunk for 100 ms and then forwards it. It preserves TCP framing and models a recovery stall, but it does not drop IP packets, trigger real TCP retransmission, or measure congestion control. It is distinct from the packet-level experiment below.

### Valid scoped Windows packet-level run

Bean Network Tester v0.8.0 was checksum-verified and run with its narrowed filter against the project proxy process, loopback, and destination port 5556. The impairment was configured for 5% loss over 90 seconds. Its final report confirms **355 scoped packets and 19 dropped packets (5.35% effective loss)**. This is packet-level loss, not the proxy's intact-chunk hold.

Forty handshakes ran while the same filter was active: ten adaptive trials and ten each with fixed ML-KEM-512, ML-KEM-768, and ML-KEM-1024. All 40 completed the handshake and server replay check. The adaptive policy selected ML-KEM-768 in all ten runs.

| Condition | n | Median handshake | Mean ± sample SD | Over 200 ms | Success |
|---|---:|---:|---:|---:|---:|
| Adaptive (selected ML-KEM-768) | 10 | 19.934 ms | 83.952 ± 128.424 ms | 2/10 | 10/10 |
| Fixed ML-KEM-512 | 10 | 21.063 ms | 22.336 ± 7.138 ms | 0/10 | 10/10 |
| Fixed ML-KEM-768 | 10 | 19.862 ms | 82.068 ± 130.244 ms | 2/10 | 10/10 |
| Fixed ML-KEM-1024 | 10 | 29.843 ms | 162.414 ± 327.049 ms | 2/10 | 10/10 |

The 200–1,051 ms tail observations are consistent with TCP recovery delays, but this setup does not directly count per-handshake retransmissions. The effective 5.35% loss rate is for the **combined** 40-trial emulator session, not a separately measured rate for each profile. Profile differences are exploratory because each profile did not receive its own independent emulator report. All traffic was loopback on one machine. The earlier process-name-filtered report (`real_loss_trial1.json`) had zero scoped packets and is excluded.

Machine-readable results: [`real_loss_trials_5pct.json`](real_loss_trials_5pct.json), [`real_loss_5pct_summary.csv`](real_loss_5pct_summary.csv), [`real_loss_handshake_samples.csv`](real_loss_handshake_samples.csv), and the three fixed-profile sample CSVs. Reproduce handshake trials while a similarly scoped packet-loss run is active with `run_phase7_real_loss_trials.py` and `run_phase7_real_loss_fixed_controls.py`; summarize only a report with confirmed scoped drops using `summarize_phase7_loss.py`.

The proxy's rate limiting for bandwidth conditions still applies to chunks returned by TCP reads, so OS segmentation and scheduling affect observed pacing.

## Expanded latency and bandwidth grid

A repeatable runner now covers additional conditions with three trials each. Replay rejection was confirmed for all 18 handshakes.

| Condition | Policy-selected profile | Median handshake | Mean ± sample SD |
|---|---|---:|---:|
| RTT 40 ms | ML-KEM-768 | 61.990 ms | 66.226 ± 11.897 ms |
| RTT 160 ms | ML-KEM-768 | 187.670 ms | 192.343 ± 15.625 ms |
| 256 kbps, no bandwidth input | ML-KEM-768 | 206.258 ms | 206.286 ± 2.330 ms |
| 256 kbps, bandwidth-aware policy | ML-KEM-512 | 183.563 ms | 181.404 ± 5.097 ms |
| 2,048 kbps, bandwidth-aware policy | ML-KEM-512 | 44.003 ms | 45.268 ± 4.857 ms |
| 100,000 kbps, bandwidth-aware policy | ML-KEM-768 | 34.528 ms | 34.960 ± 0.925 ms |

The policy chose ML-KEM-512 at the two lower bandwidth settings, where the smaller hello exchange reduces estimated transfer time, and returned to ML-KEM-768 at 100,000 kbps, where the recorded handshake median favors 768. Under 256 kbps, the observed 512 median was about 11% lower than the default 768 median. These are local proxy results with three runs per point, not general network performance claims.

Run the full grid with:

```powershell
python .\experiments\run_phase7_grid.py --runs 3
```

The runner saves individual outcomes to [`network_condition_grid_samples.csv`](network_condition_grid_samples.csv), aggregates to [`network_condition_grid_summary.csv`](network_condition_grid_summary.csv), and proxy flow logs to `grid_proxy_connections.csv`.

The grid expands RTT and bandwidth coverage. The loss-like hold and packet-level loss measurements are separate conditions; do not combine their measurements or labels.
