# Phase 6: ML-KEM profile comparison

## Why compare profiles first?

Phase 6 begins by making the cryptographic parameter set an explicit, measurable choice. The benchmark now accepts `--kem ml-kem-512`, `--kem ml-kem-768`, or `--kem ml-kem-1024`. Each uses the same benchmark procedure: five warmup batches, then 30 measured batches of 100 operations for each primitive. Three separate process runs were recorded per profile.

This isolates ML-KEM profile as the independent variable. It provides inputs for a later policy, while keeping the policy itself out of this experiment. The policy must have a security floor; it must not choose a weaker profile solely because it is faster or smaller.

## Results

See [`mlkem_primitive_samples.csv`](mlkem_primitive_samples.csv) for all 27 profile/run/operation observations and [`mlkem_parameter_summary.csv`](mlkem_parameter_summary.csv) for the across-run means and standard deviations. Sizes are reported by the linked liboqs implementation.

The profile sizes are:

| Profile | Public key | Ciphertext | Secret key |
|---|---:|---:|---:|
| ML-KEM-512 | 800 B | 768 B | 1,632 B |
| ML-KEM-768 | 1,184 B | 1,088 B | 2,400 B |
| ML-KEM-1024 | 1,568 B | 1,568 B | 3,168 B |

In these pilot runs, mean key generation was about 18.3 µs, 36.3 µs, and 51.0 µs respectively; mean encapsulation was about 23.0 µs, 37.6 µs, and 54.4 µs; mean decapsulation was about 27.8 µs, 46.9 µs, and 65.2 µs. Values are specific to this host, build, and provider; they are not universal performance claims.

## How to interpret this

The public key is sent by the responder in the KEM public-key message; the ciphertext is returned by the initiator in the encapsulation response. Their sum is the basic two-message KEM payload, before framing, signatures, X25519 material, and other handshake fields. The profile affects both computational work and communication overhead. A real handshake comparison is still needed because its total time includes serialization, authentication, network delay, and other crypto.

A sensible future decision path is: first filter profiles that meet the configured minimum security requirement, then choose among the remaining profiles using measured latency, payload budget, and network conditions. Record the policy inputs, selected profile, and reason for each decision. Bind the selected profile to the authenticated handshake transcript and reject downgrade attempts.

## Scope and limitations

This is a primitive and fixed-profile handshake pilot, not a security proof or complete adaptive-agility demonstration. It exercises all three profiles in the authenticated handshake, but the profile is selected by the paired executable build and does not yet adapt to changing runtime measurements or network conditions. Timing depends on host load and compiler/library configuration. Repeat on controlled hosts before making publication-grade claims.

## Full handshake comparison

The fixed-profile authenticated handshake was built as matched client/server pairs for all three profiles. The profile identifier is included in both hello messages, checked against the peer build, and included in the ML-DSA-65 signed authentication transcript. Phase 6 uses protocol version 2 and a new transcript domain separator so these packets are not confused with the earlier wire format. Each profile had three loopback runs. See [`handshake_profile_samples.csv`](handshake_profile_samples.csv) for individual trials and [`handshake_profile_summary.csv`](handshake_profile_summary.csv) for aggregate statistics.

| Profile | Median CLIENT_HELLO-to-key | CLIENT_HELLO | SERVER_HELLO | Total hello bytes on loopback |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 6.267 ms | 833 B | 4,113 B | 4,958 B |
| ML-KEM-768 | 5.726 ms | 1,217 B | 4,433 B | 5,662 B |
| ML-KEM-1024 | 6.931 ms | 1,601 B | 4,913 B | 6,526 B |

The total includes the 6-byte framing header on each hello. `SERVER_HELLO` is dominated by the fixed 3,309-byte ML-DSA-65 signature, so the KEM ciphertext changes the total by hundreds of bytes rather than accounting for the entire packet. All nine handshakes completed and all nine replay checks passed. Timing spread is visible even across three loopback trials; these are pilot results and do not show that one profile is consistently fastest. Notice that the ML-KEM-512 primitive benchmark was fastest, but the full handshake medians do not rank profiles in that same order. That is expected: the full timer also includes signature verification, X25519, HKDF, packet I/O, scheduling, and measurement noise. Policy decisions should be based on end-to-end measurements and repeated trials, not primitive timings alone.

A mismatched fixed-profile ML-KEM-512 client and ML-KEM-768 server were rejected at packet validation. The adaptive client/server pair added below can select a profile at runtime; the server supports all three and enforces a configurable minimum. The selected ID is echoed in `SERVER_HELLO` and included in the ML-DSA-65 signed transcript.

The measured handshake timer is client-side from `CLIENT_HELLO` send through authenticated session-key readiness. TCP connect is reported separately in client logs; client KEM key generation and server process startup are outside this interval. Comparisons use the same host, executable build settings, authentication keys, and loopback path. Do not compare these values directly to a different testbed or treat them as a cryptographic security ranking.


## Policy selection prototype

`phase6_policy_demo.exe` applies an explicit policy to the Phase 6 measurements. Its inputs are a minimum permitted profile, an optional available bandwidth, an optional maximum estimated handshake time, and an objective (`latency` or `bandwidth`). It first filters out profiles below the minimum and those over the latency ceiling. It then chooses the lowest estimated end-to-end time or, for the bandwidth objective, the smallest hello exchange. If nothing remains eligible, it fails closed.

The transfer estimate is `total hello bytes × 8 / bandwidth_kbps` milliseconds. This accounts only for the two handshake hello messages; it does not model later encrypted application traffic, packet loss, retransmission, or variable RTT. The baseline latency values are only three-run medians from the current loopback setup, so this is an experiment prototype rather than a production policy.

Examples:

- No arguments uses a minimum profile of 768 and the latency objective, selecting ML-KEM-768 from the current measurements.
- `phase6_policy_demo.exe --minimum 512 --objective bandwidth` selects ML-KEM-512 because it has the smallest measured hello exchange.
- `phase6_policy_demo.exe --minimum 512 --bandwidth-kbps 1000 --max-handshake-ms 48` selects ML-KEM-512; the larger profiles exceed the estimated latency ceiling.
- `phase6_policy_demo.exe --minimum 768 --bandwidth-kbps 1000 --max-handshake-ms 48` finds no eligible profile and exits without selecting one.

The configured minimum profile is a policy floor, not an automatically established security certification. The adaptive live handshake uses runtime-sized KEM lengths and server-side minimum enforcement. The decision table is currently calibrated from this project's recorded pilot CSV and the bandwidth estimate is supplied by the operator; it does not yet measure changing conditions itself. The fixed-profile executables remain available for controlled comparisons. Further work should gather live network telemetry, test profile-ID tampering and downgrade rejection explicitly, and repeat the performance experiments with more trials.

## Runtime adaptive handshake

New targets `client_auth_phase6_adaptive` and `server_auth_phase6_adaptive` support all three ML-KEM profiles in one client/server build. The client invokes the policy selector before creating its KEM key pair, sends the selected profile ID and corresponding public key, and sends a hello with that profile's exact length. The server maps the ID to the liboqs KEM, checks that the hello length matches, rejects profiles below `--minimum`, then encapsulates with that profile. The response echoes the selected ID. Both peers place the same ID and variable-length KEM values in the signed transcript; the client checks the echoed ID before accepting the response. The selected profile ID is also included in HKDF context, so different profiles derive different session keys from the same combined secret.

The adaptive packet validator accepts only the known hello lengths for ML-KEM-512, -768, and -1024. It rejects unrelated lengths before the application parser sees them. This prevents a profile byte from being treated as authoritative when the accompanying public key or ciphertext has a different size.

| Scenario | Client policy choice | Server minimum | Result | Hello-to-key time |
|---|---|---:|---|---:|
| Default latency policy | ML-KEM-768 | 768 | Handshake and replay check passed | 11.932 ms |
| Bandwidth objective, minimum 512 | ML-KEM-512 | 512 | Handshake and replay check passed | 8.108 ms |
| Minimum 1024 | ML-KEM-1024 | 1024 | Handshake and replay check passed | 7.643 ms |
| Client policy selects ML-KEM-512 | 768 | Rejected before handshake | No session key | — |

These are one-off integration checks, not comparable to the earlier three-run profile medians; startup and first-use effects vary. Raw logs and extracted outcomes are in [`adaptive_policy_handshake_samples.csv`](adaptive_policy_handshake_samples.csv). The user must configure the server minimum consistently with the policy floor that the client is allowed to select. For example, to let the client use ML-KEM-512, start the server with `--minimum 512` and run the client with `--minimum 512 --objective bandwidth`.

The server accepts one client-selected profile per session rather than sending a full supported-profile list. Runtime selection, transcript binding, and minimum enforcement are now exercised. Explicit byte-level mutation of the profile ID and downgrade attack testing remain to be done before claiming downgrade resistance has been experimentally validated.

To run the adaptive pair manually from the repository root:

1. Start `build\Release\server_auth_phase6_adaptive.exe --minimum 512`.
2. In another terminal, run `build\Release\client_auth_phase6_adaptive.exe --minimum 512 --objective bandwidth`.

The client selects ML-KEM-512 because the bandwidth objective minimizes hello bytes after the minimum-profile filter. With no client flags, the policy minimum defaults to ML-KEM-768 and the latency objective uses the recorded median handshake table. The server's minimum is enforced independently; if the client chooses below that floor, the server closes the connection before a session key is established.