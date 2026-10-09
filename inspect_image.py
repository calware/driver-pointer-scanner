"""Emit auditable static evidence without executing a driver."""
import argparse
import json
from scanner import Image

p=argparse.ArgumentParser()
p.add_argument('image')
p.add_argument('--rva',type=lambda x:int(x,0),action='append',default=[])
p.add_argument('--output',required=True)
a=p.parse_args(); im=Image(a.image)
lines=[f'IMAGE: {im.path}',f'BASE: {im.base:#x}',f'ENTRY RVA: {im.entry-im.base:#x}',
       'SECTIONS:']
for s in im.pe.sections:
    lines.append(f'{s.Name!r} RVA={s.VirtualAddress:#x} size={s.Misc_VirtualSize:#x} flags={s.Characteristics:#x}')
lines.append('IMPORTS:')
for va,name in sorted(im.imports.items()): lines.append(f'{va-im.base:#x} {name}')
for rva in a.rva:
    lines.append(f'FUNCTION RVA {rva:#x}:')
    for ins in im.instructions(im.base+rva).values():
        annotation=[]
        for op in ins.operands:
            if op.type==3 and ins.reg_name(op.mem.base)=='rip':
                va=ins.address+ins.size+op.mem.disp
                if va in im.imports: annotation.append(im.imports[va])
                if va in im.guards: annotation.append('CFG guard dispatch/check slot')
                section=im.section(va)
                if section: annotation.append(f'RVA {va-im.base:#x} {section.Name!r} writable={im.writable(va)}')
        lines.append(f'{ins.address-im.base:08x} {ins.bytes.hex():24} {ins.mnemonic:8} {ins.op_str} '+ '; '.join(annotation))
from pathlib import Path
Path(a.output).write_text('\n'.join(lines)+'\n',encoding='utf-8')
