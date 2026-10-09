"""Annotate direct slot writers with nearby dynamic-export lookup evidence."""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from capstone.x86 import X86_OP_MEM
from scanner import Image

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'reports' / 'broad-installed-enriched.json'
TARGET = HERE / 'reports' / 'broad-installed-final.json'


def import_call_name(image, ins):
    if ins.mnemonic != 'call' or not ins.operands: return None
    op = ins.operands[0]
    if op.type != X86_OP_MEM or ins.reg_name(op.mem.base) != 'rip': return None
    return image.imports.get(ins.address + ins.size + op.mem.disp)


def utf16_string(image, address):
    try:
        text = image.pe.get_data(address-image.base, 160).decode('utf-16le', errors='ignore').split('\x00')[0]
        return text if text and all(32 <= ord(c) < 127 for c in text) else None
    except Exception:
        return None


def source_hint(image, writer, code):
    pc = image.base + int(writer['instruction_rva'], 0)
    earlier = [ins for ins in code.values() if ins.address < pc and pc-ins.address <= 96]
    earlier.sort(key=lambda ins: ins.address)
    if writer['instruction'].endswith(', rax'):
        calls = [ins for ins in earlier if import_call_name(image, ins) == 'MmGetSystemRoutineAddress']
        if calls:
            call = calls[-1]
            lead = [ins for ins in earlier if ins.address < call.address and call.address-ins.address <= 64]
            for ins in reversed(lead):
                if ins.mnemonic != 'lea' or len(ins.operands) != 2:
                    continue
                if ins.reg_name(ins.operands[0].reg) != 'rdx':
                    continue
                op = ins.operands[1]
                if op.type == X86_OP_MEM and ins.reg_name(op.mem.base) == 'rip':
                    symbol = utf16_string(image, ins.address+ins.size+op.mem.disp)
                    if symbol:
                        return {'kind': 'DYNAMIC_KERNEL_EXPORT', 'symbol': symbol,
                                'lookup_call_rva': hex(call.address-image.base)}
            return {'kind': 'DYNAMIC_KERNEL_EXPORT', 'symbol': None,
                    'lookup_call_rva': hex(call.address-image.base)}
    return {'kind': 'OTHER_REGISTER_OR_MEMORY_SOURCE', 'symbol': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--output', type=Path, default=TARGET)
    args = parser.parse_args()
    rows = json.loads(args.source.read_text(encoding='utf-8'))['results']
    for index, row in enumerate(rows, 1):
        wanted = {(w['function_rva'], w['instruction_rva']) for site in row['writable_image_slot_calls']
                  for w in site.get('direct_writer_sites', [])}
        if not wanted: continue
        image = Image(row['file'])
        hints = {}
        for function_rva, instruction_rva in wanted:
            code = image.instructions(image.base+int(function_rva,0))
            writer = next(w for site in row['writable_image_slot_calls']
                          for w in site.get('direct_writer_sites', [])
                          if w['function_rva']==function_rva and w['instruction_rva']==instruction_rva)
            hints[(function_rva,instruction_rva)] = source_hint(image, writer, code)
            image.cache.pop(image.base+int(function_rva,0), None)
        for site in row['writable_image_slot_calls']:
            for writer in site.get('direct_writer_sites', []):
                writer['source_hint'] = hints[(writer['function_rva'],writer['instruction_rva'])]
        print(f'[{index}/{len(rows)}] {Path(row["file"]).name}: writers={len(wanted)}',flush=True)
    counts = collections.Counter(
        (w['source_hint']['kind'],w['source_hint'].get('symbol'))
        for row in rows for site in row['writable_image_slot_calls']
        for w in site.get('direct_writer_sites', []))
    args.output.write_text(json.dumps({'results':rows,'writer_source_summary':
        [{'kind':k[0],'symbol':k[1],'count':n} for k,n in counts.most_common()]}, indent=2),
        encoding='utf-8')
    print(counts.most_common(12))


if __name__ == '__main__': main()
