# x64 Windows driver indirect-call surface scanner

Offline defensive triage of PE driver images. The scanner reads files and writes JSON reports; it never loads drivers, opens device handles, sends IOCTLs, changes security policy, or writes to installed binaries.

## What constitutes a candidate

The current, wider user-interaction inventory is in `user_interaction_scan.py`.
It recovers WDM `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, and
`IRP_MJ_DEVICE_CONTROL` dispatch roots, plus KMDF `EvtIoDefault`, `EvtIoRead`,
`EvtIoWrite`, and `EvtIoDeviceControl` queue callbacks. It reports calls through
writable image slots, read-only image pointers, image-resident indexed pointer
tables, and separately labeled object-field indirect calls. The object-field
leads do **not** prove that the pointer is stored inside this driver image or
in a driver-owned allocation. The narrower SystemBuffer-input variant remains
a distinct `input_buffer_variant_candidate` field and the original scanner
output remains available.

```powershell
python user_interaction_scan.py --source reports\installed-verified.json --output reports\user-interaction-installed.json
```

The wider scan is static MAY reachability, not live execution proof. Driver
stack routing, device ACLs, request source, initialization state, predicates,
and service state require separate validation. A resolved entry and converged
worklist only cover the modeled graph. No host device is opened or probed.

The read-only 522-image run is in `reports/user-interaction-reviewed.json`,
with `reports/user-interaction-integrity.json` and the disassembly review in
`reports/user-interaction-manual-review.md`. It reports 171 images with an
image-resident pointer-call lead, 2 with only unresolved object-field leads,
69 with no such call in converged modeled paths, and 280 inconclusive. Six
images have read-only image-pointer calls and nine have indexed image-table
calls; 69 image-lead files corresponded to Running services in the service
inventory snapshot. These are image counts, and categories are not runtime
proof or driver-wide negative verdicts. All 522 installed images matched their
baseline SHA256 after the scan.

An initialization trace assigns a function to `DRIVER_OBJECT.MajorFunction[IRP_MJ_DEVICE_CONTROL]`. Starting at that dispatch function, bounded abstract interpretation traces `IRP.AssociatedIrp.SystemBuffer` or a value loaded from it into an x64 argument register at an indirect call through a writable, non-executable image section. CFG dispatch thunks are followed to their underlying callback slot; CFG check-only functions are not treated as callback invocation.

One supported IOCTL with some controllable input is sufficient. The driver does not have to accept every IOCTL or unconstrained input. Input buffers also exist in SystemBuffer for METHOD_IN_DIRECT and METHOD_OUT_DIRECT, not only METHOD_BUFFERED. METHOD_NEITHER is outside this particular SystemBuffer model.

This pattern does not establish an attacker-accessible pointer write, a vulnerability, arbitrary code execution, a mitigation bypass, or successful user-mode access. Device ACLs, service configuration, PnP interfaces, driver stack routing, request provenance checks, and live device availability matter. A compromised callback may also be constrained by CFG, kernel CFG, VBS/HVCI and other controls; shadow stacks address return flow, not every forward indirect call.

## Run

Requires Python 3.10+, pefile, Capstone 5, z3-solver, and Unicorn 2.x. Installed packages were used on this machine; requirements.txt supplies a reproducible dependency specification.

```powershell
Set-Location C:\Users\cal\Desktop\example-device-driver-scanner
python -m pip install -r requirements.txt
python scanner.py path\driver.sys --census --output reports\one-driver.json
python scanner.py path\driver.sys --engine fixedpoint --emulate-init --output reports\one-driver.json
python scanner.py C:\Windows\System32\drivers --output reports\directory.json
python scanner.py path\corpus --recursive --budget 30000 --depth 8 --census --output reports\corpus.json
python scanner.py path\driver.sys --census
python scanner.py path\driver.sys --offline-validate
python scanner.py path\driver.sys --offline-validate --output reports\driver-offline.json
```

`--output` is optional. Without it, `scanner.py` prints the complete JSON
document to stdout, so PowerShell redirection and pipelines work normally.
With `--output`, it writes the file and prints a short progress/summary line.

`--offline-validate` adds the broad Create/Read/Write/DeviceControl variant
inventory and bounded **synthetic** Unicorn WDM request replay. For each
prioritized callsite it records the seed request, executed instruction count,
modeled and unmodeled imports, whether the callsite was hit, and whether the
observed target equals an image-resident pointer. A partial Z3 path witness is
used to seed IOCTL values where available. `offline_evidence_score` is a
transparent 0–85 evidence ranking, not a probability of vulnerability or live
user reachability; its components and model assumptions are in the JSON.
The tiers are `STATIC_LEAD_ONLY`, `MODELED_PATH_EVIDENCE`, and
`STRONG_SYNTHETIC_EVIDENCE`; the strongest tier requires a synthetic callsite
hit. None is a live-system confirmation.
KMDF callback replay is explicitly marked unsupported by this synthetic WDM
engine, while KMDF static variants remain in the inventory. The site and
instruction budgets are configurable with `--offline-max-sites` and
`--offline-instruction-limit`. No installed driver is opened, loaded, or
modified by this stage.

The independent structural census walks unwind-described functions and identifies additional writable-slot call sites without asserting IRP provenance. It is slower, especially on GPU drivers. `structural_callback_sites` are review leads, never complete pattern matches. Non-unwind-described leaf functions are not comprehensively surveyed. The dispatch tracer can decode bounded leaf/thunk targets when reached.

## Installed driver run

```powershell
Get-CimInstance Win32_SystemDriver |
    Select-Object Name,DisplayName,State,StartMode,PathName |
    ConvertTo-Json -Depth 3 | Set-Content reports\services.json
python run_installed.py
# Repeat analysis, reusing only structural surveys with an identical SHA256:
python run_installed.py --reuse-census
# To enrich a WDM-only report produced by an earlier scanner version without
# redoing the expensive WDM pass:
python enrich_installed.py
```

The inventory includes files in System32\drivers and driver service paths in DriverStore, Program Files, and other locations. File presence or service registration does not mean a driver is running. The raw service inventory records State separately.

Reports:

- `installed-v3.json`: historical WDM/fixed-point analysis before the CFG callsite precision fix.
- `installed-v4-wdm.json`: corrected WDM dispatch analysis.
- `installed-verified.json`: final merged WDM/KMDF analysis and structural surveys.
- `integrity.json`: each scanned file's pre/post SHA256, with an equality result.
- `integrity-enriched.json`: additional before/after equality check during KMDF enrichment.
- `manual-review-v3.md`: disassembly review of all 22 preliminary WDM candidate images; the final WDM candidate set is a subset after callsite and stack-argument precision fixes.
- `manual-review-wdf.md`: disassembly review of the remaining KMDF register-argument candidate and preliminary stack-only leads.
- `services.json`: read-only Win32_SystemDriver inventory.
- `structural-survey.json`: historical first expanded scan, retained for reproducibility; its provisional findings were not confirmed.
- `cimfs-disassembly.txt`, `vmbusproxy-disassembly.txt`: manual-review evidence for historical provisional hits.
- `AsIO3-disassembly.txt`, `IOMap64-disassembly.txt`: supplementary real-driver dispatch inspection. These are not exhaustive no-match proofs.
- `fixtures.json`: fixture run with the current scanner.

No installed-driver IOCTL requests were issued. User handle accessibility and successful request execution remain unconfirmed.

The final 522-image run (`installed-verified.json`) contains 9 screening candidates, 140 images with no candidate in a converged modeled root graph, and 373 inconclusive images. WDM device-control roots were recovered in 122 images; 81 WDM analyses converged. KMDF queue callback roots were recovered in 91 of 170 images importing `WdfVersionBind`; 61 of those KMDF analyses converged. The two pre/post hashing passes report 522/522 installed images unchanged. Manual disassembly review found no confirmed installed-driver match to the full requested pattern among the remaining nine screening candidates. The included compiled fixtures provide known-positive and known-negative checks; this installed corpus did not supply a manually confirmed real positive.

## Implementation

`scanner.py` combines PE import/section/unwind/load-config parsing with bounded initialization and dispatch analyses. `init_flow.py` recovers dispatch assignments across branch joins and bulk `rep stosq` initialization. Optional `init_emulator.py` executes an image copy in Unicorn with synthetic kernel objects and modeled imports; no installed driver runs in the host kernel. `flow_engine.py` uses a terminating finite MAY dataflow over dispatch roots, recording joins and budgets. `wdf_probe.py` recovers some KMDF `EvtIoDeviceControl` registrations; `wdf_flow.py` follows recognized WDF request-input retrieval calls from those roots. WDF input-buffer provenance is distinguished from direct `IRP.AssociatedIrp.SystemBuffer` provenance.

The SMT layer checks supported CMP/TEST predicates over IOCTL values, lengths, selected buffer values and the SystemBuffer pointer. It models 32-bit IOCTL/length values consistently when extended to 64 bits. A witness requires nonempty input, a non-null SystemBuffer, and transfer method 0, 1 or 2. `SAT_PARTIAL_MODEL` means only those modeled predicates are satisfiable. It is not a runnable test case or proof that every guard, alias, allocation, caller check, or buffer content condition is satisfied. Unmodeled predicates remain unconstrained. Input byte relationships and overlapping memory reads are not modeled coherently enough for full symbolic execution.

The Unicorn initialization model is deliberately synthetic and covers selected imports. It does not emulate the Windows kernel or prove a successful real registration. Triton/Qiling availability by itself cannot supply missing framework and kernel semantics. The bounded fixed-point analysis trades path correlation for wider code coverage; branch predicates are joined, so candidates require manual inspection.

## Classification

| Value | Meaning |
|---|---|
| PATTERN_CANDIDATE | Bounded MAY dataflow places input provenance in RCX, RDX, R8, or R9 at a writable callback slot. Manual semantic validation required. |
| NO_CANDIDATE_IN_MODELED_PATHS | At least one WDM/KMDF entry root was recovered, its bounded worklist converged, and no candidate was seen in those modeled paths. This does not cover unknown callbacks, kernel semantics, or user accessibility. |
| INCONCLUSIVE | No candidate and no completed rooted path analysis. |
| ERROR | Unsupported or malformed image, unreadable file, or analysis error. |

`user_openability` always remains explicitly unconfirmed. Import names and namespace strings are only hints. The initialization phase overapproximates assignments across branches; a resolved dispatch address can be an initialization alternative, not proof that it is installed in a successful live instance. Neither the bootstrap nor dispatch phase proves success-status completion.

Taint seen only in a potential fifth-or-later stack argument is kept in `unproven_writable_indirect_calls` with `stack_only_input_lead=true`. Calling-convention slots can contain stale values; the scanner cannot infer that a callback formally consumes them. These leads remain available for manual inspection rather than being discarded.

## Limits relevant to enterprise deployment

This is a research prototype with real-binary evidence, not a validated production detector for every arbitrary driver. It has no measured recall/precision on a labeled enterprise corpus. Unrecognized KMDF layouts, dynamically resolved imports, runtime-generated callbacks, heap-object callback structures, complex aliasing, exception handling, packed/obfuscated code, stack argument taint at the final callback, unmodeled instructions and unrecognized switch patterns can prevent detection. Values in argument registers can also be incidental residue rather than formal callback arguments. Review the initial target's actual parameter use before accepting a candidate. A converged fixed-point graph establishes convergence of this abstraction, not full semantic coverage.

Known instructions/imports that terminate execution are handled to avoid continuing an error path into an unreachable callback. This is still a simplified exception model. Absolute device accessibility cannot be established from a driver image alone; runtime confirmation belongs in a dedicated test system with an explicit benign request, not a host-wide probing campaign.

## Fixture

```powershell
.\build-fixtures.ps1
python -m unittest -v test_scanner
python scanner.py fixtures --census --output reports\fixtures.json
```

The WDK and LLVM build produces ten actual unsigned AMD64 native-subsystem `.sys` images at `/Od` and `/O2`:

- positive: bounded SystemBuffer checksum via a writable global callback.
- helper: the same operation forwarded through a separate helper.
- readonly: callback slot is `const volatile`, retaining an indirect call but in read-only storage.
- unrelated: callback receives a fixed local byte array, not SystemBuffer.
- internal: callback operation registered only for internal device control, not user DeviceIoControl.

The checksum IOCTL is `0x226000` (METHOD_BUFFERED, FILE_READ_ACCESS). Input size must be 1–4096 bytes and output size at least four bytes. There is no pointer-setting IOCTL, kernel write primitive, executable-memory allocation or user-supplied code address. WDK compile-time assertions verify the x64 structure offsets used by the scanner.

The positive fixture creates `\Device\CallbackSurfaceFixture` and `\DosDevices\CallbackSurfaceFixture`, and accepts create/close. Named-device security must be supplied by a correct deployment INF. No fixture was installed, signed, loaded or runtime-tested. `/GS-` simplifies the offline fixture build; these build flags are not a production-driver template. Subsystem version 6.01 is not a claim of testing on Windows 7/10/11.

Tests cover all ten variants, relocation to another image base, malformed PE handling, contradictory predicates, signed TEST semantics, nonreturning helper flow, and the distinction between a CFG check and dispatch.

## Manual confirmation procedure

1. Resolve the dispatch registration from entry/init code; check it is IRP_MJ_DEVICE_CONTROL rather than only internal device control, WMI, or an unrelated callback.
2. Follow the call chain, IOCTL selection and all relevant guards. Confirm the input comes from SystemBuffer for a user-visible supported transfer method.
3. Verify the slot is writable data, not the import table, a CFG infrastructure pointer, or read-only storage. Check runtime initialization and any updates.
4. Inspect the callback signature/parameter use. Distinguish intentional data processing from incidental live registers at an assertion, fail-fast, tracing or cleanup callback.
5. Inspect namespace and deployment security. For runtime confirmation, use a dedicated test system and one documented benign request. Offline reports cannot certify this step.

Use `inspect_image.py image.sys --rva 0x... --output reports\evidence.txt` to emit function bytes, disassembly, import annotations and section permissions without executing the driver.

## Primary references

- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
- https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects
