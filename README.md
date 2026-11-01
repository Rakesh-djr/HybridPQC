# HybridPQC

An authenticated hybrid secure-channel research prototype built with X25519,
NIST ML-KEM, ML-DSA-65, HKDF-SHA-384, and AES-256-GCM. Phase 6 adds a policy
selector for ML-KEM-512/768/1024. Phase 7 measures latency, bandwidth, and
packet-loss conditions. Phase 8 adds a **simulated** QKD key-provider path;
it does not connect to QKD hardware or a QKD key-management service.

## Phase documentation and results

- [Phase 5: baseline performance and measurement definitions](results/phase5/README.md)
- [Phase 6: crypto-agility and policy selection](results/phase6/README.md)
- [Phase 7: network conditions and packet loss](results/phase7/README.md)
- [Phase 8: QKD key-source simulation](results/phase8/README.md)
- [Phase 9: final evaluation summary](results/phase9/final_evaluation.md)
- [Phase 9: complete project report](results/phase9/full_project_report.md)
- [Phase 9: complete project report — Word](results/phase9/full_project_report.docx)
- [Phase 9: self-contained IEEE research paper — LaTeX with inline references](results/phase9/ieee_hybridpqc.tex)
- [Phase 9: research paper draft](results/phase9/research_paper_draft.md)
- [Phase 9: editable Word paper draft](results/phase9/research_paper_draft.docx)

## Build

```powershell
cmake --build build --config Release --target client_auth_phase6_adaptive server_auth_phase6_adaptive
```

The adaptive client/server pair uses loopback port 5555. Experimental QKD
simulator targets use port 5557:

```powershell
cmake --build build --config Release --target client_auth_phase8_qkd server_auth_phase8_qkd
```

The project is a research prototype, not a production security library. Its
current Windows/liboqs build reports a compiler optimization-barrier warning;
do not make constant-time implementation claims from these measurements.
