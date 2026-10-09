# Wider user-interaction pointer-call review

This pass searches WDM Create/Read/Write/DeviceControl dispatch paths and KMDF
Default/Read/Write/DeviceControl callback paths. A reported image pointer is
used as an indirect call target in the modeled path. It does not mean a
different kernel component can write that address, or that a live user handle
and request can exercise the call. The object-field category is kept separate
because its backing allocation is not established from image bytes.

## Manually checked installed-image leads

| Image | Static check | Limit of the conclusion |
|---|---|---|
| `bthenum.sys` | `InitFlow` finds RVA `0x20327` bulk-registering dispatch RVA `0x1c150` for majors 0, 3, 4, and 14. Through helper RVAs `0x1378` and `0x1430`, Create/Read/Write/DeviceControl MAY paths load `.data` slot `0x151d8` and call via CFG dispatch at `0x13ef`/`0x14ba`. Initialization resolves `WmiTraceMessage` with `MmGetSystemRoutineAddress` at `0x1c379` and writes the result to that slot at `0x1c38c`. The service inventory says Running. | These are tracing calls gated by provider flags. The path-state pass found partial satisfiability with no modeled predicates; it did not prove tracing enabled, device access, or a live user request. |
| `mmcss.sys` | Running service. Create dispatch RVA `0xeac0` reads the IRP stack and compares the opened name against up to three Unicode names. On a match it loads one of three `.rdata` callback pointers at RVAs `0x8700`, `0x8718`, or `0x8730` (pointing to local executable RVAs `0xd7e0`, `0xc240`, and `0xd400`) and invokes through CFG dispatch at `0xeb1f`. This is a direct structural example of image-contained **read-only** function pointers selected on a Create path. | The binary supports the static path; this report did not open the device, inspect its effective ACL, or establish that a particular name can be supplied successfully in this host configuration. |
| `aehd.sys` | A device-control-rooted MAY chain reaches helper `0x20e4`. It reads local executable target RVA `0x1990` from `.rdata` slot `0x3dae0`, null-checks it, and invokes it through the CFG dispatch slot at `0x21eb`. | The Android Emulator hypervisor service was Stopped. The root-to-helper branch conditions and live user access were not confirmed. The read-only slot is a pointer-call surface, not a claimed writable target. |
| `lltdio.sys` | Create dispatch RVA `0x13eb0` reaches an indexed load from `.rdata` table beginning `0xd0f0` at `0x140f5`, followed by CFG indirect call at `0x1411c`. The first table entry points to executable RVA `0x48a0`. | The table index and all branch constraints have not been validated. The reported table RVA is its base, not proof that every entry can be selected by a user request. |
| `ndproxy.sys` | Device-control dispatch RVA `0x5450` reaches an indexed load from `.data` table beginning near `0xd008` at `0x5b1f`, followed by CFG indirect call at `0x5b24`. The first sampled entry points to executable RVA `0x13730`. | The table has interleaved non-pointer fields; its index range and runtime request conditions remain unproved. The table-base report is a review lead, not a fixed slot exploit claim. |
| `bfs.sys` | Prior broad review traced device-control dispatch `0x5aa0` to writable slot `0x1e128` and guarded call `0x72d3`; an initializer stores local executable RVA `0x77c0`. | Strong static broad match, but no successful live user request or device ACL validation. |

The disassembly evidence is in `bthenum-user-pointer-review.txt`,
`aehd-user-pointer-review.txt`, `mmcss-user-pointer-review.txt`, `lltdio-user-pointer-review.txt`,
`ndproxy-user-pointer-review.txt`, and the prior `bfs-broad-*.txt` files.

No installed driver was loaded or invoked by this review. “Actually reachable”
here means a bounded static path from a recovered request entry; it is not a
runtime witness. Confirming live reachability requires a dedicated test system
with device-stack and security context inspection plus benign documented
requests, which was outside this read-only host scan.

## Additional synthetic replay

The later offline Unicorn pass in `mmcss-offline-validation.json` executed
copied `mmcss.sys` image bytes from the recovered Create dispatch with three
synthetic file-name variants: `\MmThread`, `\Notification`, and `\TaskIndex`.
Each run hit call RVA `0xeb1f` and the observed target matched the corresponding
read-only image pointer (`0x8700`, `0x8718`, or `0x8730`). The only modeled
kernel import called before those hits was `RtlCompareUnicodeString`. This is
stronger evidence for the static Create-path interpretation, but it still does
not establish that a user can open the live device with those names.
