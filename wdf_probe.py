"""Read-only, bounded KMDF EvtIoDeviceControl registration discovery.

This deliberately reports callback roots, not IOCTL reachability or buffer flow.
The x64 offsets are from Microsoft's KMDF WDF_IO_QUEUE_CONFIG and
WdfIoQueueCreateTableIndex definitions (1.x headers):
https://github.com/microsoft/Windows-Driver-Frameworks/blob/main/src/publicinc/wdf/kmdf/1.19/wdfio.h
https://github.com/microsoft/Windows-Driver-Frameworks/blob/main/src/publicinc/wdf/kmdf/1.27/wdffuncenum.h
"""
from __future__ import annotations

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from scanner import Image, canonical

QUEUE_CREATE_INDEX = 152
QUEUE_CREATE_OFFSET = QUEUE_CREATE_INDEX * 8
EVT_IO_DEVICE_CONTROL_OFFSET = 0x28
USER_REQUEST_EVENTS = {'EvtIoDefault': 0x10, 'EvtIoRead': 0x18,
                       'EvtIoWrite': 0x20, 'EvtIoDeviceControl': 0x28}
UNKNOWN = ("unknown", 0)


def _reg(ins, op):
    return canonical(ins.reg_name(op.reg))


def _mem_address(ins, op, regs):
    mem = op.mem
    if mem.index:
        return UNKNOWN
    if mem.base and ins.reg_name(mem.base) == "rip":
        return ("image", ins.address + ins.size + mem.disp)
    if not mem.base:
        return ("absolute", mem.disp)
    base = regs.get(canonical(ins.reg_name(mem.base)), UNKNOWN)
    if base[0] in ("stack", "image", "table"):
        return (base[0], base[1] + mem.disp)
    return UNKNOWN


def _value(ins, op, regs, memory, image):
    if op.type == X86_OP_REG:
        return regs.get(_reg(ins, op), UNKNOWN)
    if op.type == X86_OP_IMM:
        return ("image", op.imm) if image.executable(op.imm) else ("constant", op.imm)
    if op.type != X86_OP_MEM:
        return UNKNOWN
    address = _mem_address(ins, op, regs)
    if address in memory:
        return memory[address]
    if address[0] == "image" and op.size == 8:
        if image.writable(address[1]):
            return ("table", 0)
        pointer = image.pointer(address[1])
        if image.executable(pointer):
            return ("image", pointer)
    if address == ("table", QUEUE_CREATE_OFFSET) and op.size == 8:
        return ("queue_create", QUEUE_CREATE_INDEX)
    return UNKNOWN


def _instructions(image, start):
    """Use runtime-function boundaries and ignore duplicate chained fragments."""
    return sorted(image.instructions(start).values(), key=lambda ins: ins.address)


def _scan_function(image, start):
    # Straight-line evidence is conservative at control-flow joins. A later
    # branch can invalidate a candidate, so registration remains a MAY result.
    regs = {"rsp": ("stack", 0)}
    memory = {}
    recent_table = None
    findings = []
    for ins in _instructions(image, start):
        ops = ins.operands
        mnemonic = ins.mnemonic
        if mnemonic == "push":
            if regs.get("rsp", UNKNOWN)[0] == "stack":
                regs["rsp"] = ("stack", regs["rsp"][1] - 8)
            else:
                regs["rsp"] = UNKNOWN
            continue
        if mnemonic == "pop":
            if ops and ops[0].type == X86_OP_REG:
                regs[_reg(ins, ops[0])] = UNKNOWN
            if regs.get("rsp", UNKNOWN)[0] == "stack":
                regs["rsp"] = ("stack", regs["rsp"][1] + 8)
            continue
        if mnemonic in ("sub", "add") and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
            name = _reg(ins, ops[0]); old = regs.get(name, UNKNOWN)
            if old[0] in ("stack", "image"):
                delta = ops[1].imm * (-1 if mnemonic == "sub" else 1)
                regs[name] = (old[0], old[1] + delta)
            else:
                regs[name] = UNKNOWN
            continue
        if mnemonic in ("mov", "lea", "movzx", "movsxd") and len(ops) == 2:
            dest, src = ops
            if mnemonic == "lea" and src.type == X86_OP_MEM:
                value = _mem_address(ins, src, regs)
            else:
                value = _value(ins, src, regs, memory, image)
            if dest.type == X86_OP_REG:
                name = _reg(ins, dest)
                regs[name] = value if dest.size == 8 else (value if value[0] == "constant" else UNKNOWN)
                if value == ("queue_create", QUEUE_CREATE_INDEX):
                    recent_table = ins.address
            elif dest.type == X86_OP_MEM:
                address = _mem_address(ins, dest, regs)
                if address[0] == "stack":
                    memory[address] = value if dest.size == 8 or (dest.size == 4 and value[0] == "constant") else UNKNOWN
            continue
        if mnemonic == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and _reg(ins, ops[0]) == _reg(ins, ops[1]):
            regs[_reg(ins, ops[0])] = ("constant", 0)
            continue
        if mnemonic != "call":
            continue
        # The common MSVC CFG thunk receives the WDF function in RAX, while
        # direct calls may use the register or [table + index*8].
        target = _value(ins, ops[0], regs, memory, image) if ops else UNKNOWN
        queue_call = target == ("queue_create", QUEUE_CREATE_INDEX)
        if not queue_call and recent_table is not None and ins.address - recent_table <= 32:
            queue_call = regs.get("rax") == ("queue_create", QUEUE_CREATE_INDEX)
        if queue_call:
            config = regs.get("r8", UNKNOWN)
            if config[0] == "stack":
                size = memory.get(config, UNKNOWN)
                for event, offset in USER_REQUEST_EVENTS.items():
                    if size[0] == 'constant' and size[1] < offset + 8:
                        continue
                    callback = memory.get(("stack", config[1] + offset), UNKNOWN)
                    if callback[0] == "image" and image.executable(callback[1]):
                        findings.append({
                            "event": event,
                            "callback_rva": hex(callback[1] - image.base),
                            "function_rva": hex(start - image.base),
                            "queue_create_call_rva": hex(ins.address - image.base),
                            "config_stack_offset": config[1],
                            "config_size": size[1] if size[0] == "constant" else None,
                            "evidence": f"WDF table index 152 call; R8 points to stack WDF_IO_QUEUE_CONFIG; executable pointer at config+0x{offset:x}",
                        })
        for volatile in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
            regs[volatile] = UNKNOWN
        recent_table = None
    return findings


def discover_wdf_io_control(image):
    """Return candidate EvtIoDeviceControl roots and auditable static evidence.

    `image` may be a scanner.Image or a path. The file is only read and parsed.
    Unknown paths, indirect configuration, and version-specific layouts are
    explicitly outside this bounded structural probe.
    """
    if not isinstance(image, Image):
        image = Image(image)
    if "WdfVersionBind" not in image.imports.values():
        return {"roots_rvas": [], "roots_by_event": {name: [] for name in USER_REQUEST_EVENTS},
                "registrations": [], "limitations": ["no_WdfVersionBind_import"]}
    registrations = []
    for start in image.functions:
        registrations.extend(_scan_function(image, start))
        # Large enterprise drivers have many thousands of unwind functions.
        # The registration pass needs only the current function's instructions.
        image.cache.pop(start, None)
    roots_by_event = {name: sorted({r['callback_rva'] for r in registrations if r['event']==name},
                                   key=lambda value: int(value,16)) for name in USER_REQUEST_EVENTS}
    roots = roots_by_event['EvtIoDeviceControl']
    return {
        "roots_rvas": roots,
        "roots_by_event": roots_by_event,
        "registrations": registrations,
        "limitations": [
            "static_may_registration_only; queue creation and user reachability are not proven",
            "straight_line_function_scan; branches, helper-written configurations, and alternate table layouts may be missed",
            "WDFREQUEST buffer retrieval must be analyzed separately; SystemBuffer is not inferred",
        ],
    }
