# Phase 9: Final Evaluation Summary

## Project claim

The project is an authenticated hybrid-channel prototype that can select an
ML-KEM profile using an explicit policy and limited measurements. It also
contains a QKD-provider simulation path. It is not a production protocol,
physical QKD implementation, or formal security proof.

The distinction from the base paper matters: Rubio García et al. already
demonstrate classical + post-quantum + QKD integration in TLS/IPsec with a
physical QKD testbed. This project's extension is narrower: a custom channel,
policy selection among ML-KEM-512/768/1024, controlled local network
experiments, and a tested QKD-provider abstraction.

## Results snapshot

| Phase | Evidence | Main result | Scope caveat |
|---|---|---|---|
| 4: Security validation | Phase 6/7/8 run logs; supplied architecture | Authenticated handshake and replay rejection are verified in retained runs; profile-floor rejection is exercised. | Individual raw logs for the earlier wrong-identity and tampering cases are absent from the current results tree. Attach those before claiming their complete pass rate. |
| 5: Baseline performance | `results/phase5/README.md` and CSVs | 10-run baseline hello-to-session-key mean 8.73 ms, median 8.71 ms, SD 0.61 ms. | Loopback; toolchain warnings mean no constant-time claim. |
| 6: Crypto-agility | `results/phase6/README.md` and CSVs | Runtime client selected across 512/768/1024; server minimum enforcement; default selected 768. | Policy uses pilot medians and operator-supplied bandwidth, not live measurement. Profile handshake pilots use n=3. |
| 7: Network conditions | `results/phase7/README.md`, raw sample CSVs and emulator JSON | 40 packet-loss trials passed; scoped emulator report: 19/355 packets dropped, 5.35% effective loss. | One mixed 90-second session; per-profile effective loss rates are not isolated. Local loopback only. |
| 8: QKD abstraction | `results/phase8/README.md`, logs, comparison CSVs | 20/20 baseline and 20/20 simulator handshakes passed; paired mean difference +0.0859 ms. | Fixed public simulator fixture; lookup latency is not real KMS/QKD latency. |

## Interpretation to use in the paper

- At 256 kbps, the policy with a bandwidth input chose ML-KEM-512 and measured
  a 183.563 ms median, compared with 206.258 ms for the no-bandwidth-input
  policy selecting ML-KEM-768. This is a three-run local result, not a general
  guarantee.
- The 5% packet-loss configuration produced 5.35% measured loss over the
  combined scoped session. All adaptive and fixed-profile trials completed,
  but some handshakes had long tails. Do not say retransmissions caused those
  delays unless TCP retransmission counters are collected.
- The QKD simulator comparison found no detectable end-to-end latency change.
  Its in-memory fixture cannot predict physical QKD, KMS, key-pool, or network
  API costs.
- The ML-KEM policy is currently operator-driven and based on a small pilot
  calibration. It does not yet adapt automatically to measured RTT or loss.

## Evidence and manuscript checklist

1. Add archived Phase 4 outputs for wrong identity, transcript/signature
   tampering, ML-KEM ciphertext tampering, X25519 public-key tampering, and
   AES-GCM ciphertext tampering. The provided architecture document lists
   these cases, but the raw logs are not present in the current results tree.
2. Repeat packet loss separately for each ML-KEM profile and at multiple loss
   rates; collect TCP retransmission counters.
3. Add host memory capacity, exact machine/build identifiers, and preserve the
   source revision/hash for reproducibility.
4. Resolve the MSVC/liboqs optimization-barrier warning before making any
   implementation-level constant-time claim.
5. Keep the QKD result labelled as a simulator until a real authenticated
   key-management source is integrated and evaluated.

## Files to read

- [Research paper draft](research_paper_draft.md)
- [Phase 5 baseline and measurement definitions](../phase5/README.md)
- [Phase 6 crypto-agility and policy results](../phase6/README.md)
- [Phase 7 latency, bandwidth, and packet-loss results](../phase7/README.md)
- [Phase 8 QKD-simulator results](../phase8/README.md)
