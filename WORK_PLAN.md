# Verification plan

| Slice | Purpose | Depends on | Parallel | Functional validation | Done criterion |
|---|---|---|---|---|---|
| fixtures | Compile bounded checksum drivers | none | no | build-fixtures.ps1; test_scanner | Positive, helper, readonly, fixed-buffer and internal-only variants built at Od/O2 and scanner tests pass |
| installed | Exercise current engine on real installed binaries | fixtures | no | run_installed.py --reuse-census | All 522 inventory paths scanned; before/after hashes compared |
| review | Independently review candidate semantics and implementation | installed | yes, read-only | Disassembly evidence and independent review | Every dataflow candidate has an explicit manual outcome |
| handoff | Save reproducible commands and evidence | review | no | Re-run unit tests; open output report | README, reports and source archive available |

Assumptions: scanner never loads a driver, changes installed files, opens device handles or sends IOCTLs. User accessibility therefore remains unconfirmed. Static scan output is triage evidence, never a vulnerability declaration. Integer solver models are partial and cannot certify a whole execution path.
