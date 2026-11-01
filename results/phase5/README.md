# Phase 5 handshake baseline

## What was measured

`handshake_samples.csv` contains ten client-side measurements from the
Phase 4.6 fixed authenticated client/server pair. Both programs ran on the
same Windows machine and communicated over the loopback address
`127.0.0.1`.

- `tcp_connect_ms`: elapsed time around the client's TCP `connect()` call.
- `hello_to_session_key_ms`: elapsed time from immediately before sending
  `CLIENT_HELLO` until the hybrid session key has been derived.
- `connect_plus_handshake_ms`: sum of those two measured intervals. This
  excludes console logging between the intervals.
- `server_replay_rejected`: confirms the server log reported the repeated
  sequence number as stale and printed its replay-protection success result.

The handshake interval includes sending the framed client hello, server-side
handshake processing and response, receiving and verifying the signed server
hello, ML-KEM decapsulation, X25519 derivation, and HKDF. It excludes process
startup, Winsock/library initialization, client key generation (which occurs
before connecting), server startup and key loading, and encrypted application
data processing. Replay detection occurs after the timer stops.

## Pilot summary

| Measure | Mean | Median | Minimum | Maximum | Standard deviation |
|---|---:|---:|---:|---:|---:|
| TCP connect | 2.02 ms | 1.68 ms | 1.36 ms | 4.98 ms | 1.01 ms |
| CLIENT_HELLO to session key | 8.73 ms | 8.71 ms | 8.05 ms | 10.29 ms | 0.61 ms |
| Connect plus handshake | 10.75 ms | 10.48 ms | 9.56 ms | 13.11 ms | 0.99 ms |

All ten trials confirmed server-side replay rejection. Keep all samples when
reporting the mean; trial 7's longer TCP connection is part of the observed
variation, not a reason to discard that run.

## Environment and limitations

- CPU: Intel Core Ultra 5 125H, 14 cores and 18 logical processors.
- OS: Windows build 26300.
- Build: Visual Studio 18 CMake generator, Release configuration.
- OpenSSL: 3.6.4.
- liboqs: local static Release library from `C:\liboqs\build`.
- Installed RAM was not available from the restricted system-information
  query and should be added before final publication.
- The liboqs build emits a warning that its compiler does not provide the
  usual optimization-barrier guarantee. The link also warns that static
  liboqs uses `LIBCMT` while OpenSSL uses the DLL runtime. Treat these numbers
  as pilot measurements until the dependency build configuration is aligned
  and the experiment is repeated.
- Loopback measurements do not model physical network latency, packet loss,
  or bandwidth limits. Those belong in the network-condition phase.

These measurements are specific to this machine, software build, and local
loopback setup. They are not directly comparable to the base paper's TLS or
IPsec testbed results.

## CPU and memory pilot

`resource_pilot_samples.csv` contains ten client/server process-pair runs.
The client cycle counter spans TCP connect through session-key readiness.
The server counter spans `accept()` through session-key readiness. The
counter records main-thread CPU cycles while the thread is executing; it is
not whole-system CPU utilization and should not be converted to milliseconds
without a controlled processor-frequency model. The measured intervals also
include any console status messages emitted within them, so the values reflect
this prototype's current execution path, not only cryptographic instructions.

The memory counters are read inside each process before cleanup. Peak working
set is the largest resident set observed over that process lifetime. Private
usage is private committed memory, not resident RAM. Both process lifetimes
include startup, key setup, handshake, and the replay demonstration.

| Process metric | Client mean | Server mean |
|---|---:|---:|
| Main-thread cycles in measured interval | 7,669,566 | 25,307,750 |
| Peak working set | 9.52 MiB | 9.49 MiB |
| Private usage | 2.83 MiB | 2.84 MiB |

The client and server cycle intervals cover different work, so their cycle
counts are not a direct role-to-role efficiency comparison. All ten server
processes also confirmed replay rejection. These are pilot measurements from
the current build and the same dependency/runtime caveats apply.

## Handshake stage timings

`handshake_stage_samples.csv` records ten wall-clock samples for each timed
stage. Client receive time can overlap server computation: while the client
waits for `SERVER_HELLO`, the server is generating keys and signing. Therefore
do not add client and server stage times together. Wall-clock stage times can
also include OS scheduling pauses.

| Role and stage | Median | Range |
|---|---:|---:|
| Client receive `SERVER_HELLO` | 7.30 ms | 0.02–7.99 ms |
| Server X25519 key generation | 6.13 ms | 5.38–6.69 ms |
| Server ML-DSA-65 signing | 0.50 ms | 0.31–1.55 ms |
| Server ML-KEM-768 encapsulation | 0.34 ms | 0.31–0.56 ms |
| Client ML-DSA-65 verification | 0.37 ms | 0.22–0.82 ms |

The server's X25519 key-generation helper is much slower here than the warm
primitive benchmark. Reused-context and fresh-context helper timings were
added to distinguish per-call setup from first-use initialization. The same
comparison is included for HKDF, whose protocol helper creates its KDF
context per handshake.

## First-use versus warmed crypto initialization

The primitive benchmark now has isolated fresh-process modes. Each trial
starts a new process and performs one OpenSSL operation before any earlier
OpenSSL cryptographic call in that process. Results are in
`cold_start_samples.csv`.

| Operation | Fresh-process first-use median | Warm-path comparison |
|---|---:|---:|
| X25519 key generation | 7.883 ms | 0.059 ms with a fresh context in the warmed primitive process |
| HKDF helper | 2.579 ms | 0.0068 ms with a fresh helper in the warmed primitive process |

The current test server accepts one client and exits, so each handshake trial
starts a new server process. The server's 6.13 ms median X25519 key-generation
stage is consistent with paying a first-use initialization cost on every
trial. A long-running server would pay that cost at startup or its first
handshake, then likely use the warmed path. This is strong evidence for a
cold-start effect, but a persistent-server experiment is needed to confirm
the warm-handshake latency directly. Do not call the cold-start cost pure
X25519 computation.

## Cold versus pre-warmed server handshake

`handshake_cold_samples.csv` and `handshake_warm_samples.csv` were collected
with the same instrumented client. The warmup server variant initializes
X25519 and HKDF before it starts listening; it uses dummy inputs only for
initialization and does not change the measured handshake's algorithms or
keys. It still starts a new process for each trial, so this is a pre-warmed
process comparison rather than a persistent-server benchmark.

| Client-side interval | Cold server median | Pre-warmed server median |
|---|---:|---:|
| TCP connect | 1.52 ms | 1.59 ms |
| `CLIENT_HELLO` through session-key ready | 9.95 ms | 2.78 ms |
| Connect plus handshake | 11.50 ms | 4.53 ms |

The pre-warmed handshake interval is about 72% lower by median. TCP connect
time is nearly unchanged. The stage samples support the explanation: server
X25519 key generation fell from 6.13 ms median to 0.10 ms, and client wait
for `SERVER_HELLO` fell from 7.30 ms to 1.42 ms. Server HKDF also fell from
0.35 ms to 0.05 ms. Replay rejection was confirmed for all cold and warm
trials. This points to first-use crypto initialization as a useful
optimization target; a persistent-server run remains necessary for final
steady-state results.

## Primitive benchmark pilot

`primitive_pilot_samples.csv` preserves three independent runs of each of
the 18 primitive/message-size cases. Each run warms up with five batches,
then times 100 operations in each of 30 batches. The reported `mean_us` is
the per-operation average for one run; the min, max, and standard deviation
describe variation among that run's 30 batch averages.

| Operation | Mean across 3 runs |
|---|---:|
| X25519 key generation, reused context | 52.92 us |
| X25519 key generation, fresh context | 59.16 us |
| X25519 shared-secret derivation, reused context | 43.57 us |
| X25519 shared-secret derivation, fresh helper | 52.15 us |
| ML-KEM-768 key generation | 51.05 us |
| ML-KEM-768 encapsulation | 56.20 us |
| ML-KEM-768 decapsulation | 67.98 us |
| ML-DSA-65 key generation | 172.58 us |
| ML-DSA-65 signing | 578.33 us |
| ML-DSA-65 verification | 150.85 us |
| HKDF-SHA-384, reused context | 6.10 us |
| HKDF-SHA-384, fresh helper | 6.84 us |
| AES-GCM encrypt, 64 B | 1.00 us |
| AES-GCM encrypt, 1 KiB | 1.17 us |
| AES-GCM encrypt, 16 KiB | 5.03 us |

The AES timings include resetting and initializing the OpenSSL cipher context,
but exclude random nonce generation. Dividing payload bytes by the per-message
time gives an effective payload throughput; this is useful for comparing the
three sizes, but it is not a network throughput measurement.

These are pilot values, not final paper results. The compiler/runtime warnings
above remain unresolved, and future comparison runs should use a consistent
dependency build, repeated sessions, and the same documented system state.

## AES-GCM effective throughput

`aes_throughput_pilot.csv` derives effective payload throughput from each AES
timing run using `payload_bytes / mean_us`. With bytes and microseconds, the
result is decimal MB/s. It is a conversion of the primitive benchmark, not a
separate wire-speed measurement.

| Operation | Mean effective throughput across 3 runs |
|---|---:|
| AES-GCM encrypt, 64 B | 67.1 MB/s |
| AES-GCM decrypt, 64 B | 75.2 MB/s |
| AES-GCM encrypt, 1 KiB | 912.9 MB/s |
| AES-GCM decrypt, 1 KiB | 949.8 MB/s |
| AES-GCM encrypt, 16 KiB | 3,413.8 MB/s |
| AES-GCM decrypt, 16 KiB | 3,506.8 MB/s |

The small-message figures are lower because fixed per-call cipher setup costs
are divided across fewer payload bytes. The large-message figures better show
bulk AES processing. All exclude random nonce generation and network costs;
the compiler/runtime warnings above also apply.

## Protocol communication overhead

`communication_overhead.csv` records exact application-protocol sizes derived
from the current field definitions. The unauthenticated network payloads for
the two handshake messages total 5,648 bytes; the two six-byte protocol
headers bring that to 5,660 application-protocol bytes. The ML-DSA-65
signature is the largest field at 3,309 bytes.

These are serialized protocol sizes, not captured wire traffic. TCP may split
or coalesce writes into segments, and transport, IP, link-layer headers,
acknowledgements, and retransmissions are not included. The encrypted-message
row gives the exact framing formula as a function of plaintext length.
