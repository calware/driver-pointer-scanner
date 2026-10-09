"""Read-only direct-writer evidence for broad writable-slot call leads.

This finds explicit RIP-relative stores to each candidate image slot. Absence
does not prove no writer: base-register aliases, memcpy, relocations, and
framework writes can initialize a slot without such an instruction.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from capstone import CS_AC_WRITE
from capstone.x86 import X86_OP_MEM

from scanner import Image

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'reports' / 'broad-installed.json'
TARGET = HERE / 'reports' / 'broad-installed-enriched.json'


def direct_writers(image, slots, function_budget=50000):
    wanted = set(slots)
    writers = collections.defaultdict(list)
    starts = sorted(image.functions)
    scanned = 0
    for start in starts[:function_budget]:
        scanned += 1
        for ins in image.instructions(start).values():
            for op in ins.operands:
                if op.type != X86_OP_MEM or not (op.access & CS_AC_WRITE):
                    continue
                if ins.reg_name(op.mem.base) != 'rip' or op.mem.index:
                    continue
                address = ins.address + ins.size + op.mem.disp
                if address in wanted:
                    writers[address].append({'function_rva': hex(start-image.base),
                        'instruction_rva': hex(ins.address-image.base),
                        'instruction': ins.mnemonic+' '+ins.op_str,
                        'width_bytes': op.size})
        image.cache.pop(start, None)
    return writers, {'functions_scanned': scanned, 'functions_total': len(starts),
                     'complete_unwind_function_scan': scanned == len(starts)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--output', type=Path, default=TARGET)
    parser.add_argument('--function-budget', type=int, default=50000)
    parser.add_argument('--resume-after', type=int, default=0)
    args = parser.parse_args()
    rows = json.loads(args.source.read_text(encoding='utf-8'))['results']
    if args.resume_after:
        previous = json.loads(args.output.read_text(encoding='utf-8'))['results']
        if len(previous) != len(rows): raise RuntimeError('checkpoint length mismatch')
        rows[:args.resume_after] = previous[:args.resume_after]
    for index, row in enumerate(rows, 1):
        if index <= args.resume_after: continue
        sites = row['writable_image_slot_calls']
        if sites:
            image = Image(row['file'])
            if hashlib.sha256(image.raw).hexdigest() != row['sha256']:
                raise RuntimeError('installed image changed: '+row['file'])
            slots = {image.base+int(site['slot_rva'],0) for site in sites}
            writers, coverage = direct_writers(image, slots, args.function_budget)
            row['writer_scan_coverage'] = coverage
            for site in sites:
                slot = image.base+int(site['slot_rva'],0)
                pointer = image.pointer(slot)
                site['initial_pointer_value_rva'] = (hex(pointer-image.base)
                    if pointer and image.section(pointer) else None)
                site['initial_pointer_is_zero'] = pointer == 0
                site['direct_writer_sites'] = writers.get(slot, [])[:32]
                site['slot_initialization_evidence'] = (
                    'INITIAL_EXECUTABLE_TARGET' if image.executable(pointer) else
                    'DIRECT_WRITER_SEEN' if writers.get(slot) else
                    'INITIAL_NONZERO_TARGET_UNRESOLVED' if pointer else
                    'ZERO_INITIALIZED_NO_DIRECT_WRITER_SEEN')
        print(f'[{index}/{len(rows)}] {Path(row["file"]).name}: '
              f'sites={len(sites)}', flush=True)
        if index % 10 == 0:
            args.output.write_text(json.dumps({'results': rows, 'progress': index}, indent=2),
                                   encoding='utf-8')
    args.output.write_text(json.dumps({'results': rows}, indent=2), encoding='utf-8')
    counts = collections.Counter(s['slot_initialization_evidence'] for row in rows
                                 for s in row['writable_image_slot_calls'])
    print(dict(counts))


if __name__ == '__main__': main()
