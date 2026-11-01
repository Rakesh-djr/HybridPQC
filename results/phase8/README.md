# Phase 8: QKD key-source abstraction

## Purpose

The Phase 6 channel already combines an X25519 shared secret and an ML-KEM
shared secret with HKDF-SHA-384. Phase 8 introduces a third input through a
provider interface so the same session-key schedule can later accept key
material supplied by a QKD key manager.

The flow in the demo is:

```text
X25519 secret ─┐
ML-KEM secret ─┼─ length-delimited input key material ─ HKDF-SHA-384 ─ AES-256 key
QKD key ───────┤                       + transcript hash
transcript ────┘
```

Each endpoint requests the same opaque QKD key ID from its local provider.
Matching output is combined with the endpoint's classical and post-quantum
secrets and the handshake transcript hash. If the QKD provider cannot return
key material, a QKD-required session fails closed. Key bytes are not intended
to be logged and are cleared from the demo's working buffers when done.

## What is implemented

- `src/qkd_key_provider.h` defines the provider result codes and key-fetch API.
- `src/qkd_key_provider.c` implements a **fixed simulator fixture** and a
  process-local one-use pool plus a length-delimited HKDF-SHA-384 combiner.
- `src/phase8_qkd_demo.c` models the two endpoints, confirms matching provider
  output, binds derivation to a transcript hash, and checks that both derive
  the same 256-bit session key.
- `client_auth_phase8_qkd` and `server_auth_phase8_qkd` are separate adaptive
  handshake builds on port 5557. They ask the simulator provider for a key and
  combine it with X25519 and the negotiated ML-KEM secret. Their QKD-mode KDF
  also incorporates the SHA-384 hash of the authenticated handshake transcript.
  After the replay check, the server returns a replay verdict authenticated
  with HMAC-SHA-384 under the session key; the client waits for and verifies
  that verdict before reporting completion.
- `CMakeLists.txt` adds the `phase8_qkd_demo` executable.

Build and run from the project root:

```powershell
cmake --build build --config Release --target phase8_qkd_demo
.\build\Release\phase8_qkd_demo.exe
```

The simulator-only handshake can be run in two terminals:

```powershell
.\build\Release\server_auth_phase8_qkd.exe
.\build\Release\client_auth_phase8_qkd.exe
```

The demo passes the matching-key case, rejects a missing key ID, rejects
re-use of a consumed ID within one provider process, and confirms that
mismatched keys derive different session keys. The integrated handshake passes
with ML-KEM-768 and the client verifies the server's session-key HMAC replay
verdict. Logs are in `qkd_ack_client.log` and `qkd_ack_server.log`.

Empty-pool mode can be selected with `PHASE8_SIMULATOR_EMPTY=1`. It was run
once with the server empty and once with the client empty. In both cases the
endpoint whose pool was empty failed closed, the peer could not complete the
protocol, and the client exited with failure. Logs are in
`server_empty_pool_v2.*`, `server_empty_client_v2.*`,
`client_empty_pool_v2.*`, and `client_empty_server_v2.*`.

## Repeated paired comparison

`experiments/run_phase8_comparison.py` runs baseline and simulator handshakes
in randomized order within each pair. Both use the same adaptive selection
floor (ML-KEM-768), restart the single-session server for each trial, and
require both client completion and the server's replay-protection result.
The run used 20 pairs (20 trials per condition), seed `20261101`; all 40
handshakes succeeded and both conditions selected ML-KEM-768.

| Condition | n | Median handshake | Mean ± sample SD |
|---|---:|---:|---:|
| Baseline adaptive | 20 | 8.8795 ms | 9.9504 ± 2.4462 ms |
| QKD simulator | 20 | 8.8995 ms | 10.0363 ± 2.5806 ms |

The paired mean difference (simulator minus baseline) was +0.0859 ms, with a
2.7759 ms sample SD of paired differences. The difference is tiny compared
with run-to-run variation; these measurements show **no detectable latency
change** from the simulator in this setup. The simulator-provider lookup
median was 0.00785 ms (about 7.9 microseconds) and the QKD-mode HKDF-combine
median was 0.1399 ms. Lookup time is only an in-memory fixture and local
process check; it does not represent device or QKD key-manager latency.

The individual rows and exact per-run logs are in
`comparison_samples.csv` and `comparison_runs/`; aggregates are in
`comparison_summary.csv`. Reproduce with:

```powershell
cmake --build build --config Release --target client_auth_phase8_qkd server_auth_phase8_qkd
python .\experiments\run_phase8_comparison.py --pairs 20 --seed 20261101
```

The standalone demo also checks two negative cases: an unavailable key ID
fails closed, and changing one endpoint's QKD bytes makes the derived session
keys differ. That mismatched-key check is a KDF agreement check, not a network
attack test.

## Security and interpretation

The simulator's fixed key is public test data. Its one-use check only exists
in process memory and resets when the program restarts; it does not prevent
key reuse across restarts. It demonstrates plumbing and key composition only;
it gives **no QKD security**, secrecy, entropy, device
authentication, or key-management guarantees. The current demo also uses
fixed illustrative X25519 and ML-KEM inputs rather than running a network
handshake. It does not alter the Phase 6/7 client or server.

A real provider must obtain fresh, synchronized keys from authenticated QKD
key-management endpoints, enforce key IDs and consumption/expiry rules, avoid
key reuse, and report outages. The QKD distribution path must itself be
authenticated. QKD augments the channel's key sources; it does not replace
identity authentication or the transcript-bound handshake. For paper claims,
describe this stage as a **QKD key-source abstraction/simulation**, not a QKD
implementation.

## Remaining Phase 8 work

1. Design authenticated signaling/negotiation for a real provider. The
   current port-5557 builds require the simulator key ID out of band.
2. Replace the fixture with a QKD key-management adapter and add a fresh,
   single-use key pool before making any real-QKD claim.
3. Compare no-QKD and simulated-QKD handshakes over repeated trials; measure
   provider lookup delay, key consumption, and empty-pool behavior.

Phase 7 now includes a scoped packet-level loss run, while the proxy's intact
chunk hold remains a separate approximation. See the Phase 7 report for the
combined-session loss rate and the per-profile sample-size limitations.
