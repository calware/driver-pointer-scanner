# Installed-driver manual review — 2026-10-09

Historical provisional candidates were inspected by the primary analyst and independently reviewed. Neither was confirmed as a meaningful SystemBuffer-to-callback operation. The corrected scanner emits neither as a candidate.

## cimfs.sys

- SHA256: `116b77f4d17694409a3e202308776882f045554ed8c615c3442df539625f0df7`
- Device-control dispatch RVA: `0x2a70`.
- Provisional chain: `0x2a70 -> 0x62a0 -> 0xa454 -> 0xe838 -> 0x2b090`.
- Slot RVA `0x37000` resides in writable `.data`; initial target RVA `0xe7b0`.
- Wrapper `0xe838` loads the slot into RAX and invokes CFG dispatch thunk `0x2b090`.
- Initial target bytes at `0xe7b0`: `33 c9 cd 29 c3` = `xor ecx,ecx; int 0x29; ret`.
- This is a fail-fast operation. It does not consume the putative incoming SystemBuffer argument. The buffer value reported in RDX was incidental register residue.
- Helper `0xa454` tests SystemBuffer/length consistency and reaches the failure wrapper on null-buffer error paths; the historical partial witness did not prove a valid user request.
- Outcome: **rejected as confirmation of the requested meaningful data-parameter pattern**. Presence of a writable fail-fast callback is still a separate forward-control-flow surface under a hypothetical prior pointer corruption.

Full static evidence: `cimfs-disassembly.txt`.

## vmbusproxy.sys

- SHA256: `10915cbc92de7b95ccdc79cb6a9aa96b4f0190bc8b291f75fa47d78abcadbdca`
- Device-control dispatch RVA: `0x3ef0`.
- Provisional chain: `0x3ef0 -> 0x628c -> 0x2198 -> 0xa260`.
- Slot RVA `0xe000` resides in writable `.data`; initial target RVA `0x2140`.
- Wrapper `0x2198` loads the slot into RAX and invokes CFG dispatch thunk `0xa260`.
- Initial target bytes at `0x2140`: `33 c9 cd 29 c3` = `xor ecx,ecx; int 0x29; ret`.
- This is again a fail-fast callback with no meaningful inbound data parameter. Historical tainted argument registers do not establish intentional input passing.
- Outcome: **rejected as confirmation of the requested meaningful data-parameter pattern**. Current modeled non-null input constraints and error-flow handling eliminate the provisional report.

Full static evidence: `vmbusproxy-disassembly.txt`.

## Additional spot checks

`AsIO3.sys` dispatch RVA `0x1950` and `IOMap64.sys` dispatch RVA `0x25e0` were inspected with saved disassembly. These checks help validate that the tool recognizes real driver dispatch roots and exposes auditable code. They are not exhaustive proofs that either driver lacks the pattern, and no vulnerability conclusion was drawn.

## Interpretation

The final installed scan found no candidates requiring further full-pattern confirmation. Most images remained inconclusive. These results demonstrate that the scanner reads and analyzes installed enterprise/vendor images and rejects two concrete error-path false positives after review; they do **not** demonstrate sensitivity to positive examples in real enterprise drivers or establish that this system contains no matching drivers.

All inspection was offline. No CreateFile on device paths, IOCTL, driver installation/loading, pointer modification or installed-file mutation occurred. User accessibility is unconfirmed.
