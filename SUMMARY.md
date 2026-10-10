# Driver scanner research run

## Current wider result (Create/Read/Write/DeviceControl)

`user_interaction_scan.py` now scans WDM Create, Read, Write, and
DeviceControl roots plus KMDF Default, Read, Write, and DeviceControl roots.
It separately labels writable image slots, read-only image pointers, indexed
image pointer tables, and unresolved object-field indirect calls. The original
input-buffer argument pattern remains separately flagged.

The 522-image read-only run in `reports/user-interaction-reviewed.json` found
171 images with rooted image-pointer call leads, 2 with only object-field
leads, 69 with no such call in converged modeled paths, and 280 inconclusive.
Six images have read-only pointer calls and nine have indexed table calls.
Sixty-nine image-lead files had a Running service in the inventory snapshot.
All 522 file hashes matched the baseline after the scan. The manual review in
`reports/user-interaction-manual-review.md` confirms structural pointer-call
patterns in installed images including `mmcss.sys`, `bthenum.sys`,
`lltdio.sys`, and `ndproxy.sys`. Runtime user handle access and actual request
execution remain unverified.

The section below preserves the earlier, narrower SystemBuffer-input run.

## Synthetic replay added after the installed-image inventory

The current scanner preserves pointer provenance through `mov reg,[object+field]`
and multi-hop field loads before a register-indirect call. Those are reported as
object-field leads with the field chain and do not claim image ownership.
Unicorn now verifies transfer into the indirect target and records the concrete
synthetic request plus a short trace. `scanner.py` prints a compact witness-first
console report by default; `--format json` and `--output` retain full details.
On the installed `mmcss.sys`, the three named Create requests produce
`TARGET_ENTERED` witnesses in the current report
`reports/mmcss-concrete-witness.json`. This still does not prove a live
user-mode handle or production Windows request path.

The critical audit of the older 522-image report found 275 images without any
recovered request root. `afd.sys` was one concrete miss: whole-program
initialization exhausted its budget before a DriverEntry-reachable helper
assigned the MajorFunction table. The new local call-chain recovery found its
Create/Read/Write/DeviceIoControl roots. An indexed IOCTL code table then
yielded code `0x12003`; synthetic replay entered the table-selected target at
RVA `0x39160` from the DeviceIoControl root at `0x14cc0`, via callsite
`0x14d8e`. The witness includes one unmodeled import assumption and is not a
live handle/openability claim. See `reports/afd-concrete-witness.json`.
Among the 48 formerly rootless installed images under 64 MiB that import a
recognized `IoCreateDevice` variant, the new pass recovered WDM request roots
in 11; see `reports/local-root-recovery-sample.json`. This is a targeted
coverage audit, not a new 522-image classification tally or a precision claim.

`scanner.py --offline-validate` now adds an offline Unicorn replay and evidence
score. On the ten compiled fixtures, the four positive/helper builds and both
read-only callback builds reached their expected local targets; the two
unrelated-input builds reached their broad callback without being labeled as
the specific input-buffer variant; both internal-control builds had no user
DeviceControl lead. `reports/fixtures-offline-validation.json` records every
attempt. On installed `mmcss.sys`, synthetic Create requests with names
`\MmThread`, `\Notification`, and `\TaskIndex` reached the three `.rdata`
callback callsites and matched their initial local targets; see
`reports/mmcss-offline-validation.json`. This raises confidence in the modeled
path, while remaining separate from live user handle access or Windows I/O
manager behavior. Qiling's installed native driver loader was also probed;
it requires a Windows rootfs with registry hives not present on this machine,
so the working default uses Unicorn and explicit API models.

This project scans x64 PE driver images offline for a **screening pattern**: a recovered WDM `IRP_MJ_DEVICE_CONTROL` dispatch or KMDF `EvtIoDeviceControl` callback, a modeled request-input buffer, and an indirect call through a writable image slot with input provenance in a Windows x64 argument register. It never opens device handles, issues IOCTLs, loads drivers, or changes installed driver files. A hit is a MAY dataflow result, not proof of a feasible request, user access, pointer corruption, or arbitrary kernel execution.

## Final installed-image results

| Measure | Count |
|---|---:|
| Distinct installed images read | 522 |
| WDM device-control roots recovered | 122 |
| WDM rooted analyses converged | 81 |
| Images importing `WdfVersionBind` | 170 |
| KMDF queue callback roots recovered | 91 |
| KMDF rooted analyses converged | 61 |
| Screening candidates after callsite and stack precision fixes | 9 |
| No candidate in a converged modeled root graph | 140 |
| Inconclusive | 373 |
| Installed images unchanged by SHA256 before/after | 522/522 |
| Confirmed full-pattern match among manually reviewed candidate images | 0 |

The nine remaining candidates are `bxvbda.sys`, `cimfs.sys`, `Dbgv.sys`, `fltMgr.sys`, `fvevol.sys`, `NDKPerf.sys`, `NDKPing.sys`, `nvmedisk.sys`, and `vmbusproxy.sys`. Every one was reviewed against callsite disassembly. None currently demonstrates a valid user IOCTL carrying `SystemBuffer` or retrieved KMDF input as a meaningful argument to a writable-slot callback. Several slot targets and branches remain unresolved, so this is **not a proof of absence**.

The improved engine reduces undifferentiated inconclusives from the original 513/522 to 373/522 by recovering more WDM registration sites, finding KMDF queue callbacks, following selected WDF request-input APIs, and allowing finite dispatch graphs to converge. `NO_CANDIDATE_IN_MODELED_PATHS` refers only to those abstract graphs. It is not a whole-driver clean verdict. The WDF model distinguishes framework-retrieved input from direct `IRP.AssociatedIrp.SystemBuffer`, and it does not infer transfer method or user access from a static image.

The ten compiled x64 fixtures check the scanner: four positive/helper builds are flagged and six read-only-slot, unrelated-input, or internal-control builds are not. No fixture was installed or loaded. The installed corpus had no manually confirmed real positive, so detection on enterprise positives and recall/precision remain unvalidated.

## Reproduce and inspect

```powershell
Set-Location C:\Users\cal\Desktop\example-device-driver-scanner
python -m pip install -r requirements.txt
python -m unittest -q test_scanner test_flow_engine test_wdf_probe test_wdf_flow
python scanner.py fixtures --engine fixedpoint --emulate-init --output reports\fixtures-v3.json
python scanner.py C:\path\to\driver.sys --engine fixedpoint --emulate-init --census --output reports\one-driver.json
```

`reports/installed-verified.json` is the final machine-readable result. `reports/manual-review-v3.md` covers the 22 earlier WDM leads (including the eight removed by precision improvements), and `reports/manual-review-wdf.md` covers KMDF leads. `reports/integrity-enriched.json` contains per-image hashes. `reports/services.json` is the read-only service inventory used for the installed-image run. `reports/wdf-callsite-review.txt` contains selected KMDF callsite disassembly.

The model is bounded and discards path predicates at fixed-point joins. It can miss dynamic callback registration, alternative framework layouts, heap-resident slots, unsupported instructions, and callbacks reached through unmodeled calls. It can also flag values incidentally left in argument registers. A live handle-accessibility determination would require a controlled test environment and deployment-specific device namespace/security data; this run intentionally made no live device requests.
