# Hybrid Post Quantum Secure Channel Project Report

## Project purpose and scope

This report explains the HybridPQC research prototype from its motivation through its experiments. It is written to support a clear project presentation and a future research-paper revision. The central question is how an authenticated secure channel can combine classical and post-quantum key establishment, then choose among post-quantum parameter sets under an explicit performance policy and constrained network conditions. A separate experimental build demonstrates where an optional QKD key source could enter the session-key derivation process.

The project is an experimental custom TCP channel. It is not TLS, IPsec, a complete PKI, a formal security proof, a production cryptographic library, or a physical QKD system. Results below are measurements from one Windows host and mainly loopback networking. Where older phase logs are absent, the report describes code-level test intent and does not invent a pass count.

## Executive summary

The prototype combines X25519 and NIST ML-KEM to establish two independent shared-secret inputs, authenticates the server handshake with ML-DSA-65, combines key material with HKDF-SHA-384, and protects application data using AES-256-GCM. An explicit policy component can select ML-KEM-512, -768, or -1024 subject to a configured minimum profile. It uses recorded end-to-end handshake medians and can account for an operator-supplied bandwidth estimate. The adaptive policy is therefore a working policy-selection prototype, but not a controller that continuously measures live network conditions.

Performance experiments show why end-to-end measurement matters. ML-KEM-512 had the smallest keys and fastest primitive measurements in the pilot, but the fixed-profile handshake medians did not simply rank in the same order. Message size and local runtime initialization also affected observed handshake cost. Under the tested 256 kbps proxy condition, bandwidth-aware selection of ML-KEM-512 had a median handshake of 183.563 ms, compared with 206.258 ms for the default policy's ML-KEM-768. This was a three-run local experiment, not a general network guarantee.

A valid packet-level loss session reported 19 drops among 355 scoped packets, or 5.35% aggregate effective loss. Forty handshakes across adaptive and fixed-profile conditions all completed and passed the server replay check. Because all conditions shared one emulator session, this is not a per-profile loss rate. A QKD simulator comparison completed 20 baseline and 20 simulator handshakes; the paired mean difference was +0.0859 ms. That result only describes an in-memory fixed test fixture and must not be presented as QKD hardware or key-management performance.

## 1. Motivation

### 1.1 Why hybrid key establishment

Classical public-key systems such as elliptic-curve Diffie–Hellman are widely deployed and efficient, but a sufficiently capable quantum computer would threaten their security. There is also a present-day “harvest now, decrypt later” concern: an attacker can record encrypted traffic now and attempt to decrypt it in the future. Post-quantum cryptography is designed to resist known quantum attacks, but migration introduces interoperability and operational questions.

A hybrid key-establishment design combines a classical secret with a post-quantum secret. In this project, X25519 supplies the classical component and ML-KEM supplies the post-quantum component. The session key is derived from both inputs. The intended benefit is defense in depth during migration: a failure in one key-establishment family need not automatically reveal the final key, assuming the combiner and protocol are implemented correctly. This prototype does not provide a formal proof of that property.

### 1.2 Why crypto-agility

Post-quantum algorithms have different key sizes, ciphertext sizes, implementation costs, and deployment requirements. A fixed algorithm can become inefficient on a constrained network or unsuitable when policy requirements change. Crypto-agility is the ability to select and transition cryptographic parameters under controlled rules.

The project studies ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as selectable profiles. The policy first applies a minimum-profile floor, then chooses among eligible profiles using measured handshake medians, an optional latency ceiling, and optionally an operator-provided bandwidth estimate. The server independently enforces its minimum. The selected profile is validated, signed as part of the handshake transcript, and included in the key-derivation context. These controls reduce accidental or policy-inconsistent selection. Explicit byte-level profile-ID mutation and downgrade-attack evidence are still needed before claiming experimentally validated downgrade resistance.

### 1.3 Why measure network conditions

Post-quantum handshake messages can be much larger than classical-only exchanges. On a slow link, more bytes can matter as much as primitive runtime. Added latency and loss can also change handshake completion time and reliability. Phases 5–7 therefore progress from primitive timing to full handshake measurements and controlled network impairment. The experiments measure local behavior and are intended to guide engineering choices, not to predict every real network.

### 1.4 Why include a QKD abstraction

The supplied base paper already combines classical cryptography, post-quantum cryptography, and QKD within TLS/IPsec and reports work with a physical QKD testbed. This project does not claim that triple composition as a new idea. Its smaller extension is an interface boundary through which a QKD key provider could supply an additional key input. Phase 8 uses a simulator fixture to test that boundary and its failure behavior. A real QKD key-management integration is future work.

## 2. Research objectives and contribution

The project objectives are:

1. Build and validate the cryptographic primitives needed for an authenticated hybrid channel.
2. Combine X25519 and ML-KEM for session-key establishment and protect application messages with authenticated encryption.
3. Authenticate the server and bind handshake parameters and key material to an authenticated transcript.
4. Exercise negative security conditions, including identity errors, tampering, and replay.
5. Measure primitive cost, handshake latency, communication bytes, CPU cycles, and process memory.
6. Compare the ML-KEM profiles and implement a policy-based selection prototype with a server-enforced minimum.
7. Evaluate latency, bandwidth, and packet-loss conditions using a controlled local proxy/emulator.
8. Add and test a simulated QKD key-provider path that fails closed when required key material is unavailable.

The project contribution is an implementation-and-measurement study of these elements in a custom channel. It is not a new algorithm, a new formal cryptographic construction, or a replication of the base paper’s TLS/IPsec physical-QKD system.

## 3. Technologies and what each one does

| Technology | Role in this project | Why it is used |
|---|---|---|
| C11 | Protocol, client/server, crypto-policy, and QKD-provider code | Low-level control over message framing, cryptographic APIs, buffers, and timing instrumentation. |
| OpenSSL 3.6.4 | X25519, HKDF-SHA-384, AES-256-GCM, random bytes, and timing/resource helpers | Provides the classical and symmetric cryptographic operations and a widely used API. |
| liboqs | ML-KEM-512/768/1024 and ML-DSA-65 | Supplies the post-quantum key-encapsulation and signature implementations used by the prototype. |
| X25519 | Ephemeral classical Diffie–Hellman shared secret | Adds the classical key-establishment component to the hybrid input. |
| ML-KEM | Post-quantum key encapsulation | Adds the post-quantum shared-secret component; parameter sets enable profile comparisons. |
| ML-DSA-65 | Server handshake signature | Lets the client authenticate the server and verify transcript integrity using a provisioned trusted public key. |
| HKDF-SHA-384 | Key derivation | Combines length-delimited secret inputs and context into a fixed 256-bit AES key. |
| AES-256-GCM | Application encryption and authentication | Encrypts data and detects modification through an authentication tag. |
| Winsock/TCP | Client/server communication | Provides a simple reliable byte stream for the custom framed protocol. |
| CMake + Visual Studio | Build system and Windows C compiler/linker | Builds the protocol, tests, fixed-profile variants, adaptive targets, and simulator targets. |
| Python experiment runners | Repeatable trial orchestration and summary generation | Runs paired handshakes, controlled grid experiments, and aggregates CSV/JSON evidence. |
| Local TCP proxy | RTT delay and bandwidth pacing experiments | Provides repeatable local network-condition controls. Its stream-chunk hold case is a delay/stall approximation, not packet loss. |
| Bean Network Tester v0.8.0 | Scoped Windows packet-level loss experiment | Applies a packet drop condition to the selected local process and traffic scope. The 5.35% result is aggregate across one combined session. |
| Simulated QKD provider | Phase 8 experimental key-source boundary | Exercises matching-key, missing-key, one-use-per-process, and KDF-agreement behavior without QKD hardware. |

The local build produced an optimization-barrier warning from liboqs and a C runtime mismatch warning between static liboqs and OpenSSL. These caveats limit implementation-level security claims and make the timings provisional.

## 4. System design

### 4.1 Main components

The client makes a policy decision, creates ephemeral key material, sends a framed `CLIENT_HELLO`, authenticates the server response, derives a session key, and sends protected application data. The server validates the selected profile and message sizes, applies its configured minimum, creates its own ephemeral X25519 key pair, encapsulates to the client’s ML-KEM public key, signs the handshake transcript with ML-DSA-65, derives the same session key, and verifies protected data and replay behavior.

Authentication is server-to-client. The client’s trust anchor is a provisioned server ML-DSA public key; the project does not implement certificates, a certificate authority, or mutual client authentication. The channel uses a custom protocol and should not be treated as a replacement for a reviewed standard protocol.

### 4.2 End-to-end handshake workflow

```text
Client policy
   │  security minimum + pilot medians + optional supplied bandwidth
   ▼
Select ML-KEM profile ── reject if no profile satisfies policy
   │
   ├─ Generate ephemeral X25519 key pair
   ├─ Generate selected ML-KEM key pair
   ▼
CLIENT_HELLO: profile ID + X25519 public key + ML-KEM public key
   │
   ▼
Server validates framing, profile, exact KEM lengths, and server minimum
   ├─ Generate ephemeral X25519 key pair
   ├─ Derive X25519 shared secret
   ├─ ML-KEM encapsulate to client's public key
   ├─ Build transcript and sign with ML-DSA-65
   ▼
SERVER_HELLO: echoed profile + X25519 public key + KEM ciphertext + signature
   │
   ▼
Client verifies trusted server signature and profile echo
   ├─ ML-KEM decapsulate
   ├─ Derive X25519 shared secret
   └─ Both sides derive AES key with HKDF-SHA-384
   ▼
AES-256-GCM protected application message
   ├─ Random 96-bit nonce and 128-bit tag
   ├─ 64-bit sequence value authenticated as associated data
   └─ Server rejects stale/replayed sequence values
```

In the Phase 8 QKD simulator build, each side additionally fetches the same opaque test key ID, binds the authenticated transcript hash into the QKD-mode derivation, and includes the QKD fixture in the HKDF input. The server returns a session-key HMAC result for the replay check, which the client verifies. Missing provider material aborts the required-QKD session. This path is separate from the baseline adaptive client/server.

### 4.3 Why each cryptographic step matters

- **X25519 and ML-KEM together:** provide classical and post-quantum key-establishment inputs.
- **ML-DSA-65 transcript signature:** authenticates the server and covers the negotiated handshake values so they cannot be silently changed without detection.
- **HKDF-SHA-384:** derives a fixed-length encryption key from combined shared secrets and protocol context. It avoids using a raw shared secret directly as an AES key.
- **AES-256-GCM:** gives confidentiality and integrity for application data. A modified ciphertext or invalid tag causes authentication failure.
- **Sequence number:** provides freshness state for the replay demonstration. AEAD alone does not prevent replay; an authentic ciphertext can be resent unless the protocol tracks freshness.
- **Minimum profile policy:** stops the client from choosing below the client’s configured floor, while server-side enforcement independently refuses lower profiles.
- **Transcript/profile binding:** ties the chosen ML-KEM profile and handshake data to signature verification and key derivation, reducing cross-profile confusion.

## 5. Project phases and results

### Phase 1 — Cryptographic foundation

**Work:** Standalone tests exercise ML-KEM, X25519, the hybrid shared-secret combination, AES-GCM, and post-quantum signatures. The code uses OpenSSL for classical/symmetric primitives and liboqs for the post-quantum operations.

**Why this phase matters:** Testing primitives independently helps separate API, key-size, serialization, and correctness problems from later network-protocol bugs. It also makes the later end-to-end channel easier to reason about.

**Recorded result:** Test programs are present, including successful completion markers in the source for ML-KEM, X25519, hybrid, signature, and AES-GCM cases. The repository does not retain a Phase 1 run log or an archived numerical result set, so this report does not claim a specific historical test count. The AES-GCM test source includes a ciphertext-modification check that expects decryption authentication to fail.

### Phase 2 — Hybrid secure channel

**Work:** X25519 and ML-KEM shared secrets are combined as input keying material to HKDF-SHA-384; the derived key is used with AES-256-GCM. The hybrid test executable validates that both endpoints can derive matching key material and protect a message.

**Why this phase matters:** This confirms the main hybrid concept: the application key is derived from both a classical and a post-quantum key-establishment result rather than from either one alone.

**Recorded result:** A hybrid test implementation and success output are present in source. No standalone historical Phase 2 log or aggregate measurements are stored. The later authenticated handshake and phase benchmarks provide stronger integrated evidence, but are not a replacement for missing Phase 2 logs.

### Phase 3 — Authentication

**Work:** The server uses ML-DSA-65 to sign the handshake transcript. The client verifies that signature against a pre-provisioned trusted public key before accepting the session key. A fake server identity generator and wrong-identity test variant are present.

**Why this phase matters:** Key agreement without identity authentication can establish a key with an attacker. The signature ties the peer identity to the handshake values and lets the client detect a wrong server key or altered signed transcript.

**Recorded result:** Authentication code and test variants are present. No separate Phase 3 raw test log is retained in the results tree, so a historical success/failure count cannot be reported from saved evidence.

### Phase 4 — Security validation

**Work:** Dedicated test variants address transcript/signature tampering, wrong server identity, ML-KEM ciphertext tampering, X25519 public-key tampering, AES-GCM ciphertext tampering, and replay. The final channel versions use explicit message framing and authenticated sequence values for replay detection.

| Security case | Intended validation | Evidence currently retained |
|---|---|---|
| Transcript/signature tampering | Alter handshake transcript data and ensure signature verification fails | Test code is present; original run log is not retained. |
| Wrong identity | Verify that a fake or untrusted server public key is not accepted | Wrong-key test code is present; original run log is not retained. |
| ML-KEM ciphertext tampering | Show tampering does not yield the expected authenticated session key / is detected by subsequent authentication | Test code is present; original run log is not retained. KEM implicit-rejection behavior must not be described simply as a guaranteed decapsulation error. |
| X25519 public-key tampering | Change the peer public key and observe a changed shared secret or handshake authentication failure | Test code is present; original run log is not retained. |
| AES-GCM tampering | Modify ciphertext and expect tag verification/decryption failure | Test code is present; original Phase 4 run log is not retained. |
| Replay protection | Resend the exact prior encrypted sequence and require the server to reject it as stale | Repeated replay checks are confirmed in Phase 5, 6, 7, and 8 retained runs; all listed experimental trials passed. |

**Why this phase matters:** Positive tests show that legitimate traffic works. Negative tests show whether invalid identity, altered messages, and stale messages are rejected. The currently retained logs are strong for replay and profile-floor behavior, but individual Phase 4 mutation results need archived logs before reporting a complete pass rate for every requested attack case.

### Phase 5 — Performance benchmarking

**Method:** Handshake measurements use a client-side timer from immediately before sending `CLIENT_HELLO` until authenticated session-key readiness. It excludes process start, client KEM key generation, and application-data processing. TCP connect time is separate. Primitive measurements use three process runs for the primitive pilot; handshake and resource pilots use ten runs. Values are host/build-specific.

| Measurement | Result |
|---|---:|
| TCP connect, 10-run baseline mean / median | 2.02 / 1.68 ms |
| `CLIENT_HELLO` to session key, 10-run mean / median / SD | 8.73 / 8.71 / 0.61 ms |
| Connect plus handshake, mean / median | 10.75 / 10.48 ms |
| Client/server main-thread cycles in measured interval, mean | 7,669,566 / 25,307,750 cycles |
| Client/server peak working set, mean | 9.52 / 9.49 MiB |
| Client/server private usage, mean | 2.83 / 2.84 MiB |
| Phase 5 ML-KEM-768 profile handshake bytes, application protocol | 5,660 bytes total, including 12 framing bytes |

Representative three-run primitive means were X25519 key generation 52.92 µs with a reused context and 59.16 µs through a fresh helper; ML-KEM-768 key generation 51.05 µs, encapsulation 56.20 µs, and decapsulation 67.98 µs; ML-DSA-65 key generation 172.58 µs, signing 578.33 µs, and verification 150.85 µs; HKDF-SHA-384 6.10 µs with a reused context and 6.84 µs through a fresh helper.

AES-GCM effective payload throughput rose with message size: encryption was 67.1 MB/s at 64 bytes, 912.9 MB/s at 1 KiB, and 3,413.8 MB/s at 16 KiB. Decryption was 75.2 MB/s, 949.8 MB/s, and 3,506.8 MB/s for those sizes. These primitive calculations exclude nonce generation and network overhead; they are not wire-speed measurements.

The ten-run stage samples measured median server X25519 key generation at 6.13 ms, ML-DSA-65 signing at 0.50 ms, ML-KEM-768 encapsulation at 0.34 ms, and client ML-DSA verification at 0.37 ms. A fresh process’s first-use X25519 key-generation median was 7.883 ms versus 0.059 ms in a warmed primitive process; HKDF first-use was 2.579 ms versus 0.0068 ms in the warmed process. In a separate cold-versus-prewarmed server pilot, median handshake was 9.95 ms cold and 2.78 ms prewarmed (about 72% lower); TCP connect remained 1.52 versus 1.59 ms. This points to first-use initialization overhead, but the prewarmed server still restarted for every trial and is not a persistent-server benchmark.

### Phase 6 — Crypto-agility and comparative study

**ML-KEM profile sizes and three-run primitive means:**

| Profile | Public key | Ciphertext | Secret key | Key generation | Encapsulation | Decapsulation |
|---|---:|---:|---:|---:|---:|---:|
| ML-KEM-512 | 800 B | 768 B | 1,632 B | 18.303 µs | 23.034 µs | 27.757 µs |
| ML-KEM-768 | 1,184 B | 1,088 B | 2,400 B | 36.267 µs | 37.602 µs | 46.861 µs |
| ML-KEM-1024 | 1,568 B | 1,568 B | 3,168 B | 50.985 µs | 54.391 µs | 65.201 µs |

**Three-run fixed-profile handshake medians:**

| Profile | Median `CLIENT_HELLO` to key | Client hello | Server hello | Total application-protocol bytes |
|---|---:|---:|---:|---:|
| ML-KEM-512 | 6.267 ms | 833 B | 4,113 B | 4,958 B |
| ML-KEM-768 | 5.726 ms | 1,217 B | 4,433 B | 5,662 B |
| ML-KEM-1024 | 6.931 ms | 1,601 B | 4,913 B | 6,526 B |

All nine fixed-profile handshakes and replay checks passed. A mismatched ML-KEM-512 client and ML-KEM-768 server were rejected. The profile with the fastest primitive measurements did not have the lowest measured handshake median: the full channel also includes signing, verification, X25519, HKDF, packet I/O, scheduling, and noise.

The adaptive client supports all three profiles in one build. The policy first removes profiles below the configured minimum and profiles over an optional estimated handshake ceiling. With the latency objective, it chooses the lowest estimated handshake time; with the bandwidth objective, it chooses the smallest hello exchange. Transfer time is estimated as `8 × hello_bytes / bandwidth_kbps` milliseconds. Default selection chose ML-KEM-768; a bandwidth objective with minimum 512 chose ML-KEM-512; a minimum of 1024 selected ML-KEM-1024; and a client choosing 512 was rejected by a server minimum of 768. The one-off integration handshake times for the three accepted cases were 11.932, 8.108, and 7.643 ms respectively; do not merge these single-run values with the three-run profile medians.

The client’s profile ID and actual field lengths are checked, the server echoes the profile, both peers bind it into the signed transcript, and it is also included in the HKDF context. This supports controlled profile selection and server floor enforcement. Policy inputs are pilot medians and optional operator-supplied bandwidth, not live measurements of RTT/loss or automatic telemetry.

### Phase 7 — Network-condition experiments

The local TCP proxy adds configured RTT, paces bytes in each direction, or can hold intact stream chunks. Each condition initially used three trials.

| Condition | Selected profile | Median handshake | Mean ± sample SD | Success and replay |
|---|---|---:|---:|---|
| Baseline proxy | ML-KEM-768 | 13.339 ms | 13.913 ± 1.799 ms | 3/3 |
| 80 ms configured RTT | ML-KEM-768 | 114.508 ms | 114.973 ± 2.947 ms | 3/3 |
| 512 kbps per direction, default policy | ML-KEM-768 | 173.468 ms | 176.439 ± 54.843 ms | 3/3 |
| 512 kbps, bandwidth-aware policy | ML-KEM-512 | 108.360 ms | 106.621 ± 4.029 ms | 3/3 |
| 100 ms hold per forwarded stream chunk | ML-KEM-768 | 228.705 ms | 225.238 ± 6.227 ms | 3/3 |

The chunk-hold condition delays intact TCP stream data; it is not a packet drop and does not measure TCP retransmission or congestion control.

An expanded three-run grid produced these medians: RTT 40 ms, 61.990 ms; RTT 160 ms, 187.670 ms; 256 kbps with no bandwidth input, ML-KEM-768 at 206.258 ms; 256 kbps with bandwidth-aware policy, ML-KEM-512 at 183.563 ms; 2,048 kbps bandwidth-aware, ML-KEM-512 at 44.003 ms; and 100,000 kbps bandwidth-aware, ML-KEM-768 at 34.528 ms. All 18 handshakes completed and passed replay checks. At 256 kbps the bandwidth-aware median was about 11% lower than the no-bandwidth-input condition, but the comparison is based on three runs per point.

The separate valid packet-level loss experiment used a narrowed filter for the project proxy and backend loopback traffic. Over a single 90-second mixed-profile session, the emulator recorded 355 scoped packets and 19 dropped packets, giving 5.35% effective aggregate loss. The adaptive policy selected ML-KEM-768 for all ten adaptive trials. Ten adaptive and thirty fixed-profile handshakes all completed and passed replay checks.

| Packet-loss condition | n | Median | Mean ± SD | Over 200 ms | Completed/replay |
|---|---:|---:|---:|---:|---:|
| Adaptive (selected 768) | 10 | 19.934 ms | 83.952 ± 128.424 ms | 2/10 | 10/10 |
| Fixed ML-KEM-512 | 10 | 21.063 ms | 22.336 ± 7.138 ms | 0/10 | 10/10 |
| Fixed ML-KEM-768 | 10 | 19.862 ms | 82.068 ± 130.244 ms | 2/10 | 10/10 |
| Fixed ML-KEM-1024 | 10 | 29.843 ms | 162.414 ± 327.049 ms | 2/10 | 10/10 |

The loss percentage is aggregate for all 40 trials, not separately measured for each profile. Long-tail times are consistent with recovery delays but retransmissions were not directly instrumented, so the report does not attribute each delay to TCP retransmission. All of this traffic was loopback on one computer.

### Phase 8 — QKD key-provider abstraction

Phase 8 adds a separate simulated-provider build. Both endpoints request a matching opaque key ID. The returned test bytes are combined with X25519 and ML-KEM inputs through a length-delimited HKDF-SHA-384 input, with a hash of the authenticated transcript in the QKD-mode context. The simulator supports an empty pool and one-use-per-provider-process behavior. The client waits for the server’s session-key HMAC result confirming the replay check.

The standalone demo passed matching-key agreement, missing-key rejection, reuse rejection within one provider process, and a mismatched-key derivation check. In the integrated simulator path, empty pools on either side caused the required-QKD handshake to fail closed. The fixture is a fixed public value and resets on process restart; it provides no QKD entropy, physical key distribution, device authentication, KMS security, or durable anti-reuse protection.

Twenty randomized pairs compared baseline and QKD-simulator runs; all 20/20 handshakes succeeded in each condition and selected ML-KEM-768.

| Condition | n | Median | Mean ± sample SD |
|---|---:|---:|---:|
| Baseline adaptive | 20 | 8.8795 ms | 9.9504 ± 2.4462 ms |
| QKD simulator | 20 | 8.8995 ms | 10.0363 ± 2.5806 ms |

The paired mean difference (simulator minus baseline) was +0.0859 ms, with 2.7759 ms sample SD of paired differences. The observation is small compared with run-to-run variation. Simulator key lookup median was 0.00785 ms and QKD-mode HKDF combine median was 0.1399 ms; the lookup figure is only for an in-memory test fixture and says nothing about a real QKD key manager.

### Phase 9 — Final evaluation and research writing

Phase 9 consolidates the protocol description, measurement definitions, results, scope limits, and manuscript evidence checklist. The project-level claim is an authenticated hybrid-channel prototype with a policy selector and a simulated QKD provider boundary. The base paper comparison is explicit: its physical QKD and TLS/IPsec testbed is broader and operates at a different system scale. The project's extension is the narrow study of ML-KEM profile selection, controlled local performance/network measurements, and simulator-provider plumbing.

## 6. How to interpret the results

1. **Primitive speed does not determine whole-handshake speed.** Fixed-profile full-handshake medians vary because the signed response, X25519 initialization, verification, serialization, and scheduling contribute to time.
2. **Large handshake messages amplify network cost.** ML-KEM profiles change key and ciphertext sizes. The fixed ML-DSA-65 signature is itself a large part of the response, so changing ML-KEM does not change total bytes by the same amount as the signature size.
3. **The policy responds to its inputs, not the environment automatically.** A bandwidth input can move selection toward a smaller KEM hello exchange. The system does not continuously estimate available bandwidth, RTT, or loss.
4. **Observed medians are pilot estimates.** Most profile/network comparisons use three runs. The loss experiment has ten trials per condition but a shared aggregate loss observation; the QKD comparison has twenty randomized pairs.
5. **The QKD result is about software plumbing.** Nearly equal baseline/simulator timings are expected for an in-memory fixture and cannot predict hardware or key-manager costs.
6. **Replay protection is distinct from encryption.** AES-GCM authenticates a message, but a replayed valid message remains valid cryptographically unless freshness state rejects it. The channel’s sequence check addresses this protocol-level issue.

## 7. Limitations and claims that should not be made

- Do not call the policy autonomous live adaptation. It consumes recorded local medians and optional operator-supplied bandwidth. RTT and loss are measured in experiments but are not live policy inputs.
- Do not say the project implements QKD or that the simulator provides quantum security. It uses public fixed test bytes.
- Do not claim full empirical completion of every Phase 4 mutation case without restoring the corresponding raw logs. Code contains the test variants; saved historical output is missing.
- Do not claim downgrade resistance is comprehensively validated until profile-byte mutation and downgrade attacks are tested with archived output.
- Do not treat the 5.35% packet loss as a separate per-profile rate or claim retransmissions caused each long tail.
- Do not compare these custom-channel loopback timings directly with the base paper’s TLS/IPsec testbed.
- Do not make constant-time implementation claims. The build emitted an liboqs optimization-barrier warning and a runtime-library mismatch warning.
- Do not describe the prototype as production ready. It lacks standard protocol review, certificate infrastructure, mutual authentication, a live telemetry policy controller, multi-host tests, and a physical QKD/KMS integration.

## 8. Recommended next improvements

1. Archive reproducible Phase 4 logs for wrong identity, transcript/signature mutation, ML-KEM ciphertext mutation, X25519 public-key mutation, AES-GCM ciphertext mutation, and replay; use a test matrix with expected versus observed result.
2. Test profile-ID byte mutation and downgrade attempts. Record the policy input, chosen profile, peer response, and server floor for each case.
3. Repeat packet loss independently per profile at more than one loss rate and collect OS TCP retransmission counters.
4. Add live telemetry and a clearly bounded policy state machine if the research claim requires adaptation to measured RTT, loss, and bandwidth. Keep the minimum-security floor non-negotiable and log each decision.
5. Increase sample sizes, run repeated sessions, randomize profile ordering, and report confidence intervals where appropriate.
6. Record exact host memory, build revision, dependency hashes, compiler flags, and source commit. Resolve the liboqs compiler-barrier warning and OpenSSL/liboqs runtime mismatch before stronger performance/security claims.
7. Benchmark persistent-server steady state separately from process startup and prewarmed process trials.
8. Replace the QKD fixture with an authenticated real key-management adapter only if hardware/service access is available; specify key-ID lifecycle, expiry, synchronization, outage behavior, and downgrade policy.
9. Review the wire protocol and key schedule against established protocol design practices before any deployment consideration.

## 9. Glossary for project presentation

| Term | Plain-language meaning |
|---|---|
| KEM | A mechanism that lets one side encapsulate a secret to another side’s public key; the receiver decapsulates the same secret. |
| Shared secret | Secret bytes independently derived by both peers and not sent directly over the network. |
| Hybrid key establishment | Deriving a session key using both classical and post-quantum shared-secret inputs. |
| Transcript | The ordered handshake messages and selected parameters that both sides authenticate. |
| HKDF | A key-derivation function that turns input key material and context into purpose-specific keys. |
| AEAD | Authenticated encryption that protects confidentiality and detects modification. AES-GCM is the project’s AEAD. |
| Replay | Re-sending an earlier valid encrypted message. A freshness/sequence check is needed to reject it. |
| Crypto-agility | Policy-controlled ability to select or change cryptographic algorithms and parameters. |
| Security floor | The minimum algorithm profile policy permits, regardless of performance. |
| QKD | Quantum key distribution; in this project it is only represented by a software provider interface and public simulator fixture. |
| Loopback | Network traffic from a process back to the same machine, rather than over a physical network. |
| Median / SD | Median is the middle observation; sample standard deviation (SD) describes spread around the sample mean. |

## 10. References and project evidence

1. C. Rubio García, A. Cano Aguilera, C. Stan, J. J. Vegas Olmos, S. Rommel, and I. Tafur Monroy, “Enhanced Network Security Protocols for the Quantum Era: Combining Classical and Post-Quantum Cryptography, and Quantum Key Distribution,” *IEEE Journal on Selected Areas in Communications*, vol. 43, no. 8, pp. 2765–2781, 2025, DOI: 10.1109/JSAC.2025.3568011. Supplied local reference: `Enhanced_Network_Security_Protocols_for_the_Quantum_Era_Combining_Classical_and_Post-Quantum_Cryptography_and_Quantum_Key_Distribution.pdf`.
2. User-supplied project presentation: `Hybrid-Post-Quantum-Cryptography-for-Secure-Data-Transmission.pptx`.
3. User-supplied architecture reference: `pqc_architecture.pdf`.
4. NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
5. NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard* (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
6. RFC 7748, *Elliptic Curves for Security* (X25519): https://www.rfc-editor.org/info/rfc7748/
7. RFC 5869, *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*: https://www.rfc-editor.org/info/rfc5869/
8. NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*: https://csrc.nist.gov/pubs/sp/800/38/d/final
9. RFC 9293, *Transmission Control Protocol (TCP)*: https://www.rfc-editor.org/info/rfc9293/
10. Experiment records in `results/phase5/`, `results/phase6/`, `results/phase7/`, and `results/phase8/`; phase implementation in `src/` and build definitions in `CMakeLists.txt`.

## Appendix A — Evidence files

- Phase 5: baseline, primitive, resource, stage, warm/cold, throughput, and protocol-size CSV files in `results/phase5/`.
- Phase 6: `mlkem_primitive_samples.csv`, `mlkem_parameter_summary.csv`, `handshake_profile_samples.csv`, `handshake_profile_summary.csv`, adaptive policy samples, and client/server logs in `results/phase6/`.
- Phase 7: RTT/bandwidth grid CSVs, proxy logs, `real_loss_trials_5pct.json`, packet-loss sample CSVs, and the emulator’s narrowed-scope evidence in `results/phase7/`.
- Phase 8: randomized paired `comparison_samples.csv`, `comparison_summary.csv`, per-run client/server logs, simulator positive/negative logs in `results/phase8/`.
- Phase 4: test variants in `src/client_auth_phase4*.c`, `src/server_auth_phase4*.c`, and `src/aes_gcm_test.c`. Restore original test logs to make all historic negative-test outcomes directly auditable.
