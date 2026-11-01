# An Experimental Study of Policy-Driven Crypto-Agility in an Authenticated Hybrid Post-Quantum Channel

**Rakesh Puttala**  
Department of Computer Science and Engineering, Indian Institute of Information Technology Sri City

## Abstract

Hybrid key establishment can support migration from classical public-key cryptography to post-quantum cryptography, but practical deployments must also manage larger handshake messages, variable network conditions, and changes in available key sources. This paper presents a Windows research prototype of an authenticated secure channel that combines X25519 and NIST ML-KEM for session-key establishment, ML-DSA-65 for server authentication, HKDF-SHA-384 for key derivation, and AES-256-GCM for application data. A policy selector chooses among ML-KEM-512, ML-KEM-768, and ML-KEM-1024 using a configured minimum profile, pilot end-to-end measurements, and an operator-supplied bandwidth estimate. A separate experimental build adds a simulated QKD key-provider input and fails closed when that input is unavailable.

The evaluation includes primitive and handshake measurements, a latency/bandwidth grid, a scoped packet-loss experiment, and a randomized paired comparison of the baseline and QKD-simulator handshakes. In the packet-loss session, the emulator reported 19 dropped packets among 355 scoped packets (5.35% effective loss); all 40 handshakes completed and passed server replay checks. The adaptive policy selected ML-KEM-768 in all ten packet-loss trials. In the QKD comparison, 20 of 20 runs succeeded in each condition; the paired mean handshake difference was 0.086 ms (simulator minus baseline), small relative to observed variation. The QKD input is a public fixed fixture, not key material from QKD hardware or a QKD key-management system. Results are local prototype measurements, not production security guarantees or direct comparisons with physical QKD testbeds.

**Keywords:** post-quantum cryptography, crypto-agility, ML-KEM, ML-DSA, hybrid key establishment, network impairment, QKD key-provider abstraction

## 1. Introduction

Public-key cryptography is being updated to address the future capabilities of large-scale quantum computers. NIST standardized ML-KEM for key encapsulation and ML-DSA for digital signatures in 2024 [2], [3]. During migration, combining classical and post-quantum key-establishment inputs can preserve a classical component while adding a post-quantum component. Deployable systems must also account for the message-size and computation costs of cryptographic choices and for the network conditions under which handshakes operate.

The base paper for this project, Rubio García et al. [1], presents triple-hybrid classical, post-quantum, and QKD key establishment integrated into TLS 1.3 and IPsec/IKEv2. It reports an experimental testbed with QKD nodes, key-management systems, and optical-fiber QKD equipment. The present project follows that direction but studies a smaller custom authenticated channel. Its emphasis is policy-driven selection among ML-KEM parameter sets, repeatable measurements under controlled latency, bandwidth, and packet-loss conditions, and a QKD key-provider interface exercised with simulated key material.

The project asks: **How does policy-based ML-KEM profile selection affect handshake time and robustness under measured local network conditions, and what software boundary is needed to incorporate an optional QKD key source?** The current policy is a prototype: it uses recorded handshake medians and an operator-supplied bandwidth value. It does not continuously measure network state, learn from outcomes, or react to measured packet-loss rates.

The work makes four engineering contributions:

1. An authenticated client/server prototype combining X25519 and ML-KEM, with an ML-DSA-65 server signature over the handshake transcript.
2. Runtime profile selection and server-side minimum-profile enforcement for ML-KEM-512, -768, and -1024.
3. A repeatable local evaluation across latency, bandwidth, and a packet-level loss condition, with fixed-profile controls.
4. A QKD key-provider abstraction and separate simulator-enabled handshake build that combines a simulated QKD input with the classical and post-quantum inputs and fails closed on provider exhaustion.

This is an implementation and evaluation study. It does not claim a new cryptographic primitive, a formal proof, a real QKD implementation, or a production-ready protocol.

## 2. Related Work and Positioning

Rubio García et al. [1] combine classical, post-quantum, and QKD shared secrets in TLS 1.3 and IPsec/IKEv2. Their implementation uses an actual QKD testbed and evaluates the cost of key delivery through a QKD key-management API. Their work therefore addresses network-protocol integration and physical QKD operation at a different scale from this custom-channel prototype. Its reported measurements cannot be directly compared with the loopback results in this paper because the protocols, equipment, software stacks, and experimental topologies differ.

This paper does not treat adding a third input to HKDF as a new contribution. The incremental study is the combination of (i) profile selection from end-to-end measurements and an explicit network input, (ii) controlled comparisons over a local impairment grid including a packet-level drop report, and (iii) an isolated, failure-tested QKD-provider interface. Unlike the high-level plan in the project slides, the QKD-enabled mode does **not** silently fall back to the classical-plus-PQC mode when a key is unavailable. It fails closed; a real fallback would require explicit, authenticated downgrade policy and evaluation.

## 3. Protocol and Policy

### 3.1 Authenticated hybrid channel

The client creates an ephemeral X25519 key pair and an ML-KEM key pair for its selected profile. Its `CLIENT_HELLO` contains the X25519 public key, a profile identifier, and the corresponding ML-KEM public key. The server creates its X25519 key pair, encapsulates to the client ML-KEM public key, constructs the authentication transcript, and returns its X25519 public key, profile identifier, ML-KEM ciphertext, and ML-DSA-65 signature. The client verifies the server signature against a pre-provisioned trusted public key, checks the selected profile, decapsulates the KEM ciphertext, and derives the X25519 shared secret.

The baseline channel combines the 32-byte X25519 and 32-byte ML-KEM shared secrets and derives a 32-byte AES key with HKDF-SHA-384. The selected profile is included in the KDF context, and the handshake values are included in the signed transcript. Application messages use AES-256-GCM. An eight-byte application sequence number is authenticated as GCM associated data; the server rejects stale sequence numbers before decryption. X25519, HKDF, and GCM follow the respective protocol and standard specifications [4]–[6].

The implemented authentication is server-to-client. The client trust model uses a provisioned server public key rather than a full certificate authority or PKI. The prototype does not implement mutual client authentication.

### 3.2 Policy-driven ML-KEM selection

The policy selector evaluates profiles 512, 768, and 1024 against a configured minimum profile and an optional handshake-latency ceiling. It uses recorded profile handshake medians as the latency calibration. When a bandwidth estimate is supplied, it estimates transfer time for the two hello messages as:

\[
T_{transfer}(p) = \frac{8 \cdot B_{hello}(p)}{R_{kbps}} \text{ ms},
\]

where \(B_{hello}(p)\) is the total hello-message byte count for profile \(p\), and \(R_{kbps}\) is the supplied available bandwidth in kilobits per second. Under the latency objective, it selects the eligible profile with the lowest estimate; under the bandwidth objective, it selects the smallest hello exchange. If no profile satisfies the minimum and latency ceiling, selection fails closed.

The profile identifier and variable-length KEM data are validated by the peer, included in the signed transcript, and bound into the key context. The policy is not a live telemetry controller: bandwidth is supplied by the operator, RTT and loss are not direct policy inputs, and the latency calibration comes from small local pilots. Accordingly, this paper calls it a **policy-selection prototype**, not autonomous or production crypto-agility.

### 3.3 QKD key-source abstraction

Separate Phase 8 client and server builds request the same opaque key identifier from a local provider abstraction. The returned bytes are combined with X25519 and ML-KEM inputs using HKDF-SHA-384; the authenticated transcript hash is included in the QKD-mode KDF. A process-local simulator pool permits a key identifier to be consumed once and provides an empty-pool mode for failure injection. After the replay test, the QKD-mode server returns an HMAC-SHA-384-authenticated replay verdict under the derived session key, and the client waits for that verdict before reporting success.

The simulator key is a fixed public fixture embedded in the prototype. Its one-use state resets at process restart. It provides no QKD entropy, physical distribution, device authentication, key-management security, or durable anti-reuse guarantee. A QKD-required session aborts when its provider cannot return a key; the implementation does not automatically downgrade.

## 4. Experimental Method

### 4.1 Environment and measurements

The experiments ran on one Windows machine with an Intel Core Ultra 5 125H CPU (14 cores, 18 logical processors), Windows build 26300, Visual Studio 18, Release builds, OpenSSL 3.6.4, and a local static liboqs build. Client and server communicate over loopback, normally through a TCP impairment proxy. Installed memory capacity was not captured. The liboqs build emitted a warning that this compiler does not provide its usual optimization-barrier guarantee; the link also emitted a C runtime mismatch warning. The timing results should therefore be interpreted as prototype measurements, not evidence of constant-time execution.

The main handshake timer is measured on the client from sending `CLIENT_HELLO` through authenticated session-key readiness. It excludes process startup and client KEM key generation before the timer. TCP connection time is measured separately. Replay validation occurs after this timer. The profile comparison uses three trials per fixed profile; expanded proxy conditions use three trials per grid point; the Phase 5 baseline has ten trials; the Phase 7 packet-loss run has ten trials per condition in one continuous emulator session; and the Phase 8 QKD comparison has twenty randomized pairs per condition.

### 4.2 Packet-level loss condition

The Bean Network Tester v0.8.0 packet emulator [8] was configured for 5% loss over 90 seconds and narrowed to the project proxy process, loopback, and backend destination port 5556. The emulator's final non-simulated report recorded 355 scoped packets and 19 loss drops, yielding 5.35% effective loss. Ten adaptive trials and ten fixed-profile trials for each ML-KEM set were run while this same filter was active. Thus, 5.35% is an aggregate across the combined run; separate effective loss rates per profile were not measured. The proxy's earlier 100-ms intact-chunk hold is a different condition and is not counted as packet loss.

## 5. Results

### 5.1 Baseline and primitive costs

In ten baseline authenticated handshakes, the client-to-session-key interval had a mean of 8.73 ms, median 8.71 ms, and sample standard deviation 0.61 ms. Mean TCP connect time was 2.02 ms. The measured process-pair means were 9.52 MiB client / 9.49 MiB server peak working set and 2.83 / 2.84 MiB private usage. Main-thread cycle counts cover different role-specific intervals and are not directly comparable as efficiency scores.

Three-run primitive pilots with 3,000 iterations per sample measured ML-KEM-768 key generation at 51.05 μs, encapsulation at 56.20 μs, and decapsulation at 67.98 μs on average. ML-DSA-65 signing averaged 578.33 μs and verification 150.85 μs. HKDF-SHA-384 averaged 6.10 μs when reusing its context. These are local microbenchmarks; the full handshake also includes signing, verification, I/O, thread scheduling, and key setup.

For AES-GCM, effective throughput derived from the primitive timing pilot averaged 67.1 MB/s for 64-byte encryption, 912.9 MB/s for 1-KiB encryption, and 3,413.8 MB/s for 16-KiB encryption. These values exclude network transmission and are not wire throughput.

The fixed ML-KEM-768 hello exchange totals 5,660 application-protocol bytes, including two six-byte framing headers. The fixed-profile results are:

| Profile | Client hello payload | Server hello payload | Total application-protocol bytes* | Handshake median (n=3) | Replay checks |
|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | 833 B | 4,113 B | 4,958 B | 6.267 ms | 3/3 |
| ML-KEM-768 | 1,217 B | 4,433 B | 5,662 B | 5.726 ms | 3/3 |
| ML-KEM-1024 | 1,601 B | 4,913 B | 6,526 B | 6.931 ms | 3/3 |

*Total includes two six-byte protocol framing headers. The individual hello payload columns exclude those headers.

The ML-DSA-65 signature is 3,309 bytes and dominates the server hello. The profile medians are based on only three runs and do not establish a stable performance ranking.

### 5.2 Latency and bandwidth policy grid

Three runs were collected per point. All 18 handshakes in the expanded grid completed and passed the server replay check.

| Condition | Policy-selected profile | Median handshake | Mean ± sample SD |
|---|---|---:|---:|
| 40-ms configured RTT | ML-KEM-768 | 61.990 ms | 66.226 ± 11.897 ms |
| 160-ms configured RTT | ML-KEM-768 | 187.670 ms | 192.343 ± 15.625 ms |
| 256 kbps, no bandwidth input | ML-KEM-768 | 206.258 ms | 206.286 ± 2.330 ms |
| 256 kbps, bandwidth-aware policy | ML-KEM-512 | 183.563 ms | 181.404 ± 5.097 ms |
| 2,048 kbps, bandwidth-aware policy | ML-KEM-512 | 44.003 ms | 45.268 ± 4.857 ms |
| 100,000 kbps, bandwidth-aware policy | ML-KEM-768 | 34.528 ms | 34.960 ± 0.925 ms |

At 256 kbps, the bandwidth-aware 512 selection had an observed median about 11% below the default 768 selection. The policy returned to 768 at 100,000 kbps. This demonstrates that an explicit bandwidth input can change profile choice in this setup; it does not demonstrate live adaptation or a general-network performance gain.

### 5.3 Packet-loss results

All 40 handshakes completed and passed server replay validation. Adaptive selection chose ML-KEM-768 in all ten adaptive trials.

| Condition | n | Median | Mean ± sample SD | Trials over 200 ms |
|---|---:|---:|---:|---:|
| Adaptive (selected ML-KEM-768) | 10 | 19.934 ms | 83.952 ± 128.424 ms | 2/10 |
| Fixed ML-KEM-512 | 10 | 21.063 ms | 22.336 ± 7.138 ms | 0/10 |
| Fixed ML-KEM-768 | 10 | 19.862 ms | 82.068 ± 130.244 ms | 2/10 |
| Fixed ML-KEM-1024 | 10 | 29.843 ms | 162.414 ± 327.049 ms | 2/10 |

The tail observations (333.860 ms for adaptive 768 and 1,051.087 ms for fixed 1024) are consistent with TCP recovery delays under packet drops [7]. Per-handshake TCP retransmissions were not directly instrumented, so this causal explanation remains a hypothesis. The effective loss rate applies to the mixed 40-trial session, not to each profile independently. These small samples are exploratory, not a statistically powered profile ranking.

### 5.4 QKD-simulator comparison

Twenty randomized paired blocks compared the baseline and QKD-simulator builds. Both selected ML-KEM-768 in every run, and all 40 handshakes passed. The client-to-session-key results were:

| Condition | n | Median | Mean ± sample SD |
|---|---:|---:|---:|
| Baseline adaptive | 20 | 8.8795 ms | 9.9504 ± 2.4462 ms |
| QKD simulator | 20 | 8.8995 ms | 10.0363 ± 2.5806 ms |

The paired mean difference was +0.0859 ms (simulator minus baseline), with 2.7759 ms sample standard deviation of paired differences and an approximate paired-t 95% interval of [-1.2133, 1.3851] ms. This interval includes zero and is wide relative to the mean difference. No detectable handshake latency change was observed in this setup. The simulator provider lookup median was 0.00785 ms and the QKD-mode HKDF-combine median was 0.1399 ms. The lookup measures an in-memory fixed fixture, not a real QKD key-management API.

Provider tests confirmed that an unavailable key ID and a consumed key ID fail closed, and that mismatched simulator keys produce different derived session keys. Empty-pool tests on either endpoint caused the client to exit with failure. These tests verify prototype control flow, not physical QKD security.

## 6. Security Validation and Evidence

The protocol uses ML-DSA-65 to authenticate the server handshake transcript, AES-GCM to protect application data, and a sequence number authenticated as GCM associated data to reject replay. The retained Phase 6/7/8 records demonstrate successful authentication and server replay rejection; the adaptive server also rejects a client whose selected profile is below the configured minimum. The Phase 8 simulator client verifies a session-key HMAC from the server before reporting replay-test completion.

The project architecture document lists Phase 4 checks for transcript/tampering, wrong identity, ML-KEM ciphertext, X25519 public-key, AES-GCM payload, and replay manipulation. Per-case Phase 4 raw logs are not present in the current results directory. This draft therefore does not claim a complete empirical pass rate for those tampering cases. Before submission, preserve and attach a per-case result table and the corresponding logs, or rerun those cases against the final adaptive and QKD experimental builds.

The prototype has not undergone a formal security proof, independent code audit, or side-channel evaluation. The toolchain warning about liboqs optimization barriers is material: measured timings are not evidence of constant-time behavior.

## 7. Discussion

The results show that profile selection can respond to an explicit bandwidth estimate and that the three supported ML-KEM profiles operate in the same authenticated prototype. Larger profiles increase hello size, while handshake medians are affected by more than KEM operation time. Under the packet-loss session, all profiles completed ten handshakes, but long-tail latency appeared in 768 and 1024 samples. Since the emulator loss aggregate was not separated by profile and the number of trials is small, these observations motivate further experiments rather than a conclusion that 512 is more robust.

The QKD abstraction makes the integration boundary concrete: key acquisition is separate from the classical/PQ operations, its bytes become another KDF input, and provider failure is observable. The simulator comparison indicates that the fixture itself adds negligible measured lookup time. It says nothing about a real QKD KMS. The base paper's real QKD/TLS/IPsec measurements include key-delivery API and physical testbed behavior; comparisons require a shared protocol and testbed and are outside this study.

The policy's current inputs are incomplete for the stated long-term objective. A deployable controller should obtain authenticated or otherwise trusted telemetry for bandwidth, RTT, packet loss, and service constraints; account for provider availability; and enforce downgrade floors at both endpoints. It should also use a larger calibration set and report decision quality, not only handshake timing. The current policy is operator-driven and calibrated on small local samples.

## 8. Limitations and Future Work

1. **Network scope:** all tests use local loopback. The packet-loss session has one aggregate 5.35% effective rate; per-profile loss rates and retransmission counters are absent. Repeat each profile in an independent emulator session and add multiple loss levels and RTT combinations.
2. **Policy inputs:** available bandwidth is operator-supplied, and the policy's median table is built from small pilots. Add live telemetry, measured loss/RTT, hysteresis, and explicit downgrade tests.
3. **QKD:** the fixed public fixture is not physical QKD, has no real key-pool service, and its one-use state resets at process restart. Integrate a mock service with durable key IDs first, then a real authenticated KMS if available. Do not claim QKD security from the current simulator.
4. **Authentication and deployment:** authentication is server-only with a provisioned key. Add mutual authentication, certificate/PKI support, protocol fuzzing, and robust framing/timeouts.
5. **Security evidence:** archive the Phase 4 per-case tamper outputs and rerun high-priority tests against the final adaptive and simulator builds.
6. **Measurement quality:** align compiler/runtime settings, capture full hardware and software versions, repeat cold/warm sessions separately, increase sample counts, and collect system CPU, memory, and TCP retransmission counters.
7. **Protocol positioning:** the implementation is a custom TCP research prototype, not TLS or IPsec. Results should not be generalized to those protocols or compared numerically to the base paper's physical QKD testbed.

## 9. Conclusion

This study evaluates a policy-selection prototype for an authenticated X25519/ML-KEM channel, adds a QKD-provider simulation path, and measures handshake behavior over local proxy conditions and one scoped packet-loss session. The policy changes the selected ML-KEM profile when bandwidth is supplied, and all retained Phase 7 packet-loss trials passed their handshake and replay checks despite high latency outliers. In the QKD-simulator comparison, the observed paired latency difference was small relative to variation; the simulator does not represent real QKD infrastructure. These outcomes support the feasibility of studying crypto-agility in a small prototype, while leaving live telemetry, stronger security evidence, independent per-profile loss experiments, and real QKD key-management integration for future work.

## References

[1] C. Rubio García, A. Cano Aguilera, C. Stan, J. J. Vegas Olmos, S. Rommel, and I. Tafur Monroy, “Enhanced Network Security Protocols for the Quantum Era: Combining Classical and Post-Quantum Cryptography, and Quantum Key Distribution,” *IEEE Journal on Selected Areas in Communications*, vol. 43, no. 8, pp. 2765–2781, 2025, doi: [10.1109/JSAC.2025.3568011](https://doi.org/10.1109/JSAC.2025.3568011).

[2] National Institute of Standards and Technology, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, FIPS 203, 2024. [https://doi.org/10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203).

[3] National Institute of Standards and Technology, *Module-Lattice-Based Digital Signature Standard*, FIPS 204, 2024. [https://doi.org/10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204).

[4] A. Langley, M. Hamburg, and S. Turner, “Elliptic Curves for Security,” RFC 7748, 2016. [https://www.rfc-editor.org/rfc/rfc7748](https://www.rfc-editor.org/rfc/rfc7748).

[5] H. Krawczyk and P. Eronen, “HMAC-based Extract-and-Expand Key Derivation Function (HKDF),” RFC 5869, 2010. [https://www.rfc-editor.org/rfc/rfc5869](https://www.rfc-editor.org/rfc/rfc5869).

[6] M. Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, NIST SP 800-38D, 2007. [https://doi.org/10.6028/NIST.SP.800-38D](https://doi.org/10.6028/NIST.SP.800-38D).

[7] W. Eddy, Ed., “Transmission Control Protocol (TCP),” RFC 9293, 2022. [https://www.rfc-editor.org/rfc/rfc9293](https://www.rfc-editor.org/rfc/rfc9293).

[8] D. Babiarz, *Bean Network Tester*, v0.8.0, Windows release. [https://github.com/donislawdev/BeanNetworkTester](https://github.com/donislawdev/BeanNetworkTester).
