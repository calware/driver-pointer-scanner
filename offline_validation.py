"""Bounded, synthetic x64 WDM request replay for indirect-call triage.

Only copied PE bytes are executed in Unicorn. A hit proves execution in this
explicit model, never CreateFile access or execution on a live Windows host.
"""
from __future__ import annotations

import collections
import hashlib
import struct
from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RIP,
    UC_X86_REG_RBX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R10,
    UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15, UC_X86_REG_RBP)

from scanner import Analyzer, Image, canonical

PAGE = 0x1000
STATE = 0x60000000
STACK = 0x10000000
HEAP = 0x50000000
STUB = 0x70000000
STOP = 0x71000000
REGS = dict(zip(('rax','rcx','rdx','r8','r9','rsp','rip','rbx','rsi','rdi',
                 'r10','r11','r12','r13','r14','r15','rbp'),
                (UC_X86_REG_RAX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,
                 UC_X86_REG_R9,UC_X86_REG_RSP,UC_X86_REG_RIP,UC_X86_REG_RBX,
                 UC_X86_REG_RSI,UC_X86_REG_RDI,UC_X86_REG_R10,UC_X86_REG_R11,
                 UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15,
                 UC_X86_REG_RBP)))
MAJORS = {'CreateFile':0, 'ReadFile':3, 'WriteFile':4, 'DeviceIoControl':14}


def align(x): return (x+PAGE-1)&~(PAGE-1)


def _ioctl_candidates(image, root, site=None):
    """Seed IOCTLs from comparisons, including indexed code/handler tables."""
    candidates = [0x226000, 0x222000]
    instructions=list(image.instructions(root).values())
    for pos,ins in enumerate(instructions):
        if ins.mnemonic=='cmp':
            for op in ins.operands:
                if op.type!=X86_OP_MEM or op.size!=4 or not op.mem.index or op.mem.scale!=4:
                    continue
                base_name=canonical(ins.reg_name(op.mem.base)) if op.mem.base else None
                index_name=canonical(ins.reg_name(op.mem.index))
                if not base_name:continue
                base_va=None
                for previous in reversed(instructions[max(0,pos-16):pos]):
                    if (previous.mnemonic=='lea' and len(previous.operands)==2 and
                        previous.operands[0].type==X86_OP_REG and
                        canonical(previous.reg_name(previous.operands[0].reg))==base_name and
                        previous.operands[1].type==X86_OP_MEM and
                        previous.reg_name(previous.operands[1].mem.base)=='rip'):
                        base_va=previous.address+previous.size+previous.operands[1].mem.disp
                        break
                if base_va is None:continue
                bound=None
                for previous in reversed(instructions[max(0,pos-20):pos]):
                    if previous.mnemonic!='cmp' or len(previous.operands)!=2:continue
                    left,right=previous.operands
                    if (left.type==X86_OP_REG and right.type==X86_OP_IMM and
                        canonical(previous.reg_name(left.reg))==index_name and 1<=right.imm<=256):
                        bound=right.imm
                        break
                if bound is None:continue
                table=base_va+op.mem.disp
                discovered=[]
                for index in range(bound):
                    try:code=struct.unpack('<I',image.pe.get_data(table-image.base+4*index,4))[0]
                    except (ValueError,struct.error):break
                    if 0x10000<=code<=0xffffffff and ((code>>2)&0x3ff)==index:
                        discovered.append((index,code))
                if len(discovered)<2:continue
                if site and site.get('slot_rva') and site.get('initial_target_rva'):
                    slot=image.base+int(site['slot_rva'],0)
                    target=image.base+int(site['initial_target_rva'],0)
                    discovered.sort(key=lambda pair:image.pointer(slot+8*pair[0])!=target)
                for _,code in reversed(discovered[:12]):
                    if code not in candidates:candidates.insert(0,code)
    for ins in instructions:
        if ins.mnemonic not in ('cmp','test'):
            continue
        for op in ins.operands:
            if op.type == X86_OP_IMM and 0x10000 <= op.imm <= 0xffffffff:
                if op.imm not in candidates: candidates.insert(0,op.imm)
        if len(candidates)>=10: break
    return candidates[:12]


def _unicode_name_before_slot(image, slot):
    """Find common {UNICODE_STRING, callback} records (e.g. MMCSS Create)."""
    if slot is None: return None
    try:
        data=image.pe.get_data(slot-image.base-0x10,16)
        length,maximum,_,address=struct.unpack('<HHIQ',data)
        if not (0 < length <= maximum <= 256 and length%2==0 and image.section(address)):
            return None
        value=image.pe.get_data(address-image.base,length).decode('utf-16le')
        return value if value and all(32<=ord(c)<127 for c in value) else None
    except (ValueError,UnicodeError,struct.error):
        return None


def _cfg_dispatch_thunk(image, address):
    if not image.executable(address):return False
    first=image.instructions(address).get(address)
    if first is None or first.mnemonic!='jmp' or len(first.operands)!=1:return False
    op=first.operands[0]
    if op.type!=X86_OP_MEM or first.reg_name(op.mem.base)!='rip':return False
    slot=first.address+first.size+op.mem.disp
    return slot in image.guards and slot not in image.guard_checks


def scenarios(image, site, path=None):
    event=site['event']
    if event=='CreateFile':
        slot=image.base+int(site['slot_rva'],0) if site.get('slot_rva') else None
        name=_unicode_name_before_slot(image,slot)
        return [{'name': 'matching_name' if name else 'empty_name',
                 'file_name':name or '', 'ioctl':0,'input_length':0,'output_length':0}]
    if event in ('ReadFile','WriteFile'):
        return [{'name':f'{event.lower()}_64', 'file_name':'', 'ioctl':0,
                 'input_length':64,'output_length':64}]
    root=image.base+int(site['dispatch_rva'],0)
    codes=_ioctl_candidates(image,root,site)
    witness=(path or {}).get('witness') or {}
    if 'ioctl_0_32' in witness:
        value=int(witness['ioctl_0_32'],0)
        codes=[value]+[x for x in codes if x!=value]
    lengths=[4,64]
    if 'input_length_0_32' in witness:
        required=int(witness['input_length_0_32'],0)
        if 0<required<=4096:lengths=[required]+[x for x in lengths if x!=required]
    return [{'name':f'ioctl_{code:08x}_len{length}', 'file_name':'',
             'ioctl':code,'input_length':length,'output_length':64}
            for code in codes[:4] for length in lengths[:2]]


def _score(site, path, attempts):
    parts={'rooted_may_flow':15}
    kind=site['pointer_kind']
    parts['storage_evidence']=20 if kind in ('WRITABLE_IMAGE_SLOT','READ_ONLY_IMAGE_POINTER','IMAGE_POINTER_TABLE') else 5
    if site.get('initial_target_rva'): parts['initial_local_target']=10
    if site.get('input_buffer_variant_candidate'): parts['specific_input_variant']=5
    if path and path.get('status')=='SAT_PARTIAL_MODEL' and path.get('modeled_predicates',0):
        parts['tracked_path_predicates_sat']=10
    hits=[a for a in attempts if a.get('status') in ('CALLSITE_HIT','TARGET_ENTERED')]
    if hits:
        parts['synthetic_callsite_hit']=20
        if any(a.get('target_entered') for a in hits):parts['synthetic_target_entered']=10
        if any(a.get('target_matches_image_pointer') for a in hits):
            parts['synthetic_target_match']=10
        assumptions=min(sum(len(a.get('unmodeled_import_calls',{})) for a in hits),3)
        if assumptions:parts['unmodeled_import_penalty']=-5*assumptions
    score=min(85,max(0,sum(parts.values())))
    tier=('STRONG_SYNTHETIC_EVIDENCE' if score>=70 and hits else
          'MODELED_PATH_EVIDENCE' if score>=50 else 'STATIC_LEAD_ONLY')
    return {'value':score,'tier':tier,'scale':'0-85 OFFLINE_EVIDENCE_ONLY',
            'components':parts,'not_a_probability':True,
            'live_user_openability':'UNVERIFIED',
            'interpretation':'Ranking evidence within the synthetic/static model; not a vulnerability or live-reachability probability.'}


def _path_evidence(image, site, cache, budget):
    if site['entry_model']!='WDM' or site['pointer_kind']!='WRITABLE_IMAGE_SLOT':
        return None
    event=site['event']; root=int(site['dispatch_rva'],0)
    key=(event,root)
    if key not in cache:
        analyzer=Analyzer(image,budget=budget,depth=8)
        analyzer.phase='dispatch'
        analyzer.dispatch_major=MAJORS[event]
        analyzer.walk(image.base+root,{'rcx':('device',0),'rdx':('irp',0),'rsp':('stack',0)})
        cache[key]={(x['call_rva'],x['slot_rva']):x['modeled_path_feasibility']
                    for x in analyzer.reachable_slots.values()}
    return cache[key].get((site['call_rva'],site.get('slot_rva')))


def emulate_site(image, site, scenario, instruction_limit=30000):
    """Run one synthetic WDM dispatch; report a callsite hit before invoking it."""
    result={'scenario':scenario,'status':'NOT_RUN','instructions':0,'modeled_import_calls':{},
            'unmodeled_import_calls':{},'synthetic_request':True}
    if site['entry_model']!='WDM' or site['event'] not in MAJORS:
        result['status']='UNSUPPORTED_KMDF_CALLBACK_MODEL'; return result
    if len(image.raw)>64*1024*1024:
        result['status']='IMAGE_SIZE_LIMIT'; return result
    try:
        uc=Uc(UC_ARCH_X86,UC_MODE_64)
        mapped=image.pe.get_memory_mapped_image()
        uc.mem_map(image.base,align(max(image.pe.OPTIONAL_HEADER.SizeOfImage,len(mapped))))
        uc.mem_write(image.base,mapped)
        uc.mem_map(STUB,align(16*(len(image.imports)+8)))
        uc.mem_write(STUB,b'\xc3'*align(16*(len(image.imports)+8)))
        uc.mem_map(STOP,PAGE);uc.mem_write(STOP,b'\xf4')
        uc.mem_map(STATE,0x20000);uc.mem_map(STACK,0x100000);uc.mem_map(HEAP,0x100000)
        names={}
        for index,(address,name) in enumerate(image.imports.items()):
            thunk=STUB+16*index
            names[thunk]=name
            uc.mem_write(address,struct.pack('<Q',thunk))
        guard_dispatch=STUB+16*(len(names)+1)
        guard_check=guard_dispatch+16
        for address in image.guards:
            if image.section(address):
                uc.mem_write(address,struct.pack('<Q',guard_check if address in image.guard_checks else guard_dispatch))
        # Preserve the image's cookie. Replacing it without running the image's
        # CRT/security initialization can invalidate legitimate saved frames.
        def putq(a,v):uc.mem_write(a,struct.pack('<Q',v&0xffffffffffffffff))
        def putd(a,v):uc.mem_write(a,struct.pack('<I',v&0xffffffff))
        def getq(a):return struct.unpack('<Q',uc.mem_read(a,8))[0]
        def getus(a):
            n=struct.unpack('<H',uc.mem_read(a,2))[0]
            p=getq(a+8)
            return bytes(uc.mem_read(p,min(n,512))).decode('utf-16le','ignore') if p else ''
        irp=STATE+0x1000;ios=STATE+0x2000;dev=STATE+0x3000
        fileobj=STATE+0x4000;buf=STATE+0x5000;namebuf=STATE+0x7000
        putq(irp+0x18,buf);putq(irp+0xb8,ios);putq(ios+0x30,fileobj)
        putq(dev+0x40,STATE+0x9000)
        uc.mem_write(ios,bytes([MAJORS[site['event']]]))
        putd(ios+8,scenario['output_length'])
        putd(ios+0x10,scenario['input_length'])
        putd(ios+0x18,scenario['ioctl'])
        uc.mem_write(buf,bytes((i&0xff for i in range(min(scenario['input_length'],4096)))))
        filename=scenario['file_name'].encode('utf-16le')
        uc.mem_write(namebuf,filename+b'\0\0')
        uc.mem_write(fileobj+0x58,struct.pack('<HHI',len(filename),len(filename)+2,0))
        putq(fileobj+0x60,namebuf)
        sp=STACK+0xff000-8
        putq(sp,STOP)
        uc.reg_write(UC_X86_REG_RSP,sp)
        uc.reg_write(UC_X86_REG_RCX,dev)
        uc.reg_write(UC_X86_REG_RDX,irp)
        target_call=image.base+int(site['call_rva'],0)
        target_slot=image.base+int(site['slot_rva'],0) if site.get('slot_rva') else None
        import_calls=collections.Counter();unmodeled=collections.Counter()
        recent=collections.deque(maxlen=32)
        pending_target=None
        pending_steps=0
        heap_next=HEAP
        def allocate(size):
            nonlocal heap_next
            size=max(16,(min(int(size),0x10000)+15)&~15)
            if heap_next+size>HEAP+0x100000:raise MemoryError('synthetic heap exhausted')
            out=heap_next;heap_next+=size;return out
        def hook(emu,address,size,_):
            nonlocal pending_target,pending_steps
            result['instructions']+=1
            if image.executable(address):recent.append(hex(address-image.base))
            if pending_target is not None:
                pending_steps+=1
                if address==pending_target or pending_steps>8 or address==STOP:
                    result['target_entered']=address==pending_target
                    result['status']='TARGET_ENTERED' if result['target_entered'] else 'CALLSITE_HIT'
                    result['trace_tail_rvas']=list(recent)
                    emu.emu_stop();return
            if address==STOP:
                result['status']='RETURNED_BEFORE_CALLSITE';emu.emu_stop();return
            if result['instructions']>instruction_limit:
                result['status']='INSTRUCTION_LIMIT';emu.emu_stop();return
            if address==target_call:
                ins=image.instructions(image.base+int(site['function_rva'],0)).get(address)
                actual=0
                storage_address=None
                if ins and ins.operands:
                    op=ins.operands[0]
                    if op.type==X86_OP_REG:
                        actual=emu.reg_read(REGS.get(ins.reg_name(op.reg),UC_X86_REG_RAX))
                    elif op.type==X86_OP_MEM:
                        base_name=ins.reg_name(op.mem.base) if op.mem.base else ''
                        if base_name=='rip':
                            storage_address=ins.address+ins.size+op.mem.disp
                        else:
                            base=emu.reg_read(REGS[base_name]) if base_name in REGS else 0
                            index_name=ins.reg_name(op.mem.index) if op.mem.index else ''
                            index=emu.reg_read(REGS[index_name]) if index_name in REGS else 0
                            storage_address=base+index*op.mem.scale+op.mem.disp
                        try:actual=getq(storage_address)
                        except UcError:actual=0
                        if storage_address in image.guards and storage_address not in image.guard_checks:
                            actual=emu.reg_read(UC_X86_REG_RAX)
                    elif op.type==X86_OP_IMM:
                        actual=emu.reg_read(UC_X86_REG_RAX) if _cfg_dispatch_thunk(image,op.imm) else op.imm
                expected=image.pointer(target_slot) if target_slot else 0
                if site['pointer_kind']=='IMAGE_POINTER_TABLE' and target_slot:
                    expected_set={image.pointer(target_slot+8*i) for i in range(32)
                                  if image.section(target_slot+8*i)}
                    matched=actual in expected_set and image.executable(actual)
                else:
                    matched=bool(expected and actual==expected and image.executable(actual))
                result.update(status='CALLSITE_HIT',actual_target_rva=hex(actual-image.base) if image.section(actual) else None,
                              actual_target_in_image=image.executable(actual),
                              slot_rva=site.get('slot_rva'),
                              observed_storage_address=hex(storage_address) if storage_address is not None else None,
                              observed_storage_region=('IMAGE' if storage_address is not None and image.section(storage_address) else
                                                       'SYNTHETIC_STATE' if storage_address is not None and STATE<=storage_address<STATE+0x20000 else
                                                       'SYNTHETIC_HEAP' if storage_address is not None and HEAP<=storage_address<HEAP+0x100000 else
                                                       'UNRESOLVED_OR_REGISTER'),
                              target_matches_image_pointer=matched,
                              concrete_call_witness={
                                  'entry_rva':site['dispatch_rva'],'event':site['event'],
                                  'request':scenario,'call_rva':site['call_rva'],
                                  'target_rva':hex(actual-image.base) if image.executable(actual) else None,
                                  'pointer_kind':site['pointer_kind'],
                                  'input_pattern':'byte[i] = i & 0xff',
                                  'input_prefix_hex':bytes((i&0xff for i in range(min(scenario['input_length'],64)))).hex(),
                                  'storage_address':hex(storage_address) if storage_address is not None else None})
                if image.executable(actual):
                    pending_target=actual
                    return
                result['trace_tail_rvas']=list(recent)
                emu.emu_stop();return
            if address in (guard_dispatch,guard_check):
                if address==guard_dispatch:
                    emu.reg_write(UC_X86_REG_RIP,emu.reg_read(UC_X86_REG_RAX))
                else:
                    return_address=getq(emu.reg_read(UC_X86_REG_RSP))
                    emu.reg_write(UC_X86_REG_RSP,emu.reg_read(UC_X86_REG_RSP)+8)
                    emu.reg_write(UC_X86_REG_RIP,return_address)
                return
            name=names.get(address)
            if name is None:return
            import_calls[name]+=1
            rcx=emu.reg_read(UC_X86_REG_RCX);rdx=emu.reg_read(UC_X86_REG_RDX)
            r8=emu.reg_read(UC_X86_REG_R8)
            value=0
            try:
                if name=='IoGetCurrentIrpStackLocation':value=getq(rcx+0xb8)
                elif name=='RtlCompareUnicodeString':
                    left,right=getus(rcx),getus(rdx)
                    value=0 if (left.lower()==right.lower() if r8 else left==right) else 1
                elif name=='RtlInitUnicodeString' and rcx:
                    length=0
                    if rdx:
                        while length<512 and uc.mem_read(rdx+length,2)!=b'\0\0':length+=2
                    uc.mem_write(rcx,struct.pack('<HHI',length,length+2,0));putq(rcx+8,rdx)
                elif name in ('ExAllocatePoolWithTag','ExAllocatePool2','ExAllocatePool3'):
                    value=allocate(rdx)
                elif name in ('IofCompleteRequest','IoCompleteRequest','RtlZeroMemory','RtlCopyMemory'):
                    if name=='RtlZeroMemory' and rcx and rdx<=0x10000:uc.mem_write(rcx,b'\0'*rdx)
                    elif name=='RtlCopyMemory' and rcx and rdx and r8<=0x10000:uc.mem_write(rcx,bytes(uc.mem_read(rdx,r8)))
                elif name in ('KeBugCheck','KeBugCheckEx'):
                    result['status']='BUGCHECK_PATH';emu.emu_stop();return
                else:unmodeled[name]+=1
                emu.reg_write(UC_X86_REG_RAX,value&0xffffffffffffffff)
                ret=getq(emu.reg_read(UC_X86_REG_RSP))
                emu.reg_write(UC_X86_REG_RSP,emu.reg_read(UC_X86_REG_RSP)+8)
                emu.reg_write(UC_X86_REG_RIP,ret)
            except (UcError,MemoryError,struct.error) as exc:
                result['status']='MODEL_ERROR';result['error']=f'{name}: {exc}';emu.emu_stop()
        uc.hook_add(UC_HOOK_CODE,hook)
        result['status']='RUNNING'
        try:uc.emu_start(image.base+int(site['dispatch_rva'],0),STOP)
        except UcError as exc:
            if result['status']=='RUNNING':
                result['status']='EMU_ERROR';result['error']=str(exc)
                result['fault_rva']=hex(uc.reg_read(UC_X86_REG_RIP)-image.base)
                result['trace_tail_rvas']=list(recent)
        if result['status']=='RUNNING':result['status']='RETURNED_BEFORE_CALLSITE'
        if 'trace_tail_rvas' not in result:result['trace_tail_rvas']=list(recent)
        result['modeled_import_calls']=dict(import_calls)
        result['unmodeled_import_calls']=dict(unmodeled)
        return result
    except (UcError,MemoryError,struct.error,ValueError) as exc:
        result['status']='SETUP_ERROR';result['error']=f'{type(exc).__name__}: {exc}'
        return result


def validate_row(row, max_sites=12, instruction_limit=30000, path_budget=12000):
    """Validate one user_interaction_scan row; no installed image mutation."""
    image=Image(row['file'])
    if hashlib.sha256(image.raw).hexdigest()!=row['sha256']:
        raise RuntimeError('image changed since static scan')
    ranking={'READ_ONLY_IMAGE_POINTER':0,'IMAGE_POINTER_TABLE':1,'WRITABLE_IMAGE_SLOT':2,
             'OBJECT_FIELD_INDIRECT':3}
    sites=sorted(row.get('sites',[]),key=lambda s:(ranking.get(s['pointer_kind'],4),
               not bool(s.get('initial_target_rva')),s['event'],s['call_rva']))[:max_sites]
    cache={};out=[]
    for site in sites:
        path=_path_evidence(image,site,cache,path_budget)
        attempts=[]
        for scenario in scenarios(image,site,path):
            attempt=emulate_site(image,site,scenario,instruction_limit)
            attempts.append(attempt)
            if attempt['status']=='TARGET_ENTERED' and (attempt.get('target_matches_image_pointer') or
                                                        site['pointer_kind']=='OBJECT_FIELD_INDIRECT'):
                break
        out.append({'event':site['event'],'entry_model':site['entry_model'],
                    'pointer_kind':site['pointer_kind'],'dispatch_rva':site['dispatch_rva'],
                    'call_rva':site['call_rva'],'slot_rva':site.get('slot_rva'),
                    'field_chain':site.get('field_chain'),
                    'input_buffer_variant_candidate':site.get('input_buffer_variant_candidate',False),
                    'path_evidence':path,'attempts':attempts,
                    'validation_outcome':(
                        'SYNTHETIC_TARGET_ENTERED' if any(a['status']=='TARGET_ENTERED' for a in attempts) else
                        'CALLSITE_ONLY' if any(a['status']=='CALLSITE_HIT' for a in attempts) else
                        'UNSUPPORTED' if attempts and all(a['status'].startswith('UNSUPPORTED') for a in attempts) else
                        'EMULATION_BLOCKED' if attempts and all(a['status'] in ('EMU_ERROR','SETUP_ERROR','MODEL_ERROR','BUGCHECK_PATH','INSTRUCTION_LIMIT') for a in attempts) else
                        'NO_WITNESS'),
                    'offline_evidence_score':_score(site,path,attempts)})
    unchanged=hashlib.sha256(Path(row['file']).read_bytes()).hexdigest()==row['sha256']
    if not unchanged:raise RuntimeError('image changed during offline validation')
    return {'schema_version':1,'engine':'Unicorn synthetic WDM request replay',
            'image_sha256':row['sha256'],'sites_total':len(row.get('sites',[])),
            'sites_selected':len(out),'site_limit':max_sites,'sites':out,
            'outcomes':dict(collections.Counter(s['validation_outcome'] for s in out)),
            'installed_image_unchanged':unchanged,
            'evidence_scope':'Synthetic model only. No live device, OS I/O manager, real KMDF queue, handle ACL, or user request was exercised.',
            'no_live_reachability_claim':True}


def main():
    import argparse
    import json
    from pathlib import Path
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True,
                   help='JSON report from user_interaction_scan.py or reports/user-interaction-reviewed.json')
    p.add_argument('--output',type=Path,help='Write JSON report here; omit for JSON on stdout')
    p.add_argument('--names',nargs='*',default=[],help='Only these image basenames (case-insensitive)')
    p.add_argument('--max-images',type=int,default=0,help='Zero means all selected images')
    p.add_argument('--max-sites',type=int,default=12)
    p.add_argument('--instruction-limit',type=int,default=30000)
    p.add_argument('--path-budget',type=int,default=12000)
    a=p.parse_args()
    if a.max_images<0 or min(a.max_sites,a.instruction_limit,a.path_budget)<1:
        p.error('invalid budget')
    rows=json.loads(a.source.read_text(encoding='utf-8'))['results']
    wanted={x.lower() for x in a.names}
    rows=[r for r in rows if not wanted or Path(r['file']).name.lower() in wanted]
    if a.max_images:rows=rows[:a.max_images]
    results=[]
    for index,row in enumerate(rows,1):
        try:
            result=validate_row(row,a.max_sites,a.instruction_limit,a.path_budget)
            result['file']=row['file']
        except Exception as exc:
            result={'file':row['file'],'status':'ERROR',
                    'error':f'{type(exc).__name__}: {exc}',
                    'no_live_reachability_claim':True}
        results.append(result)
        if a.output:print(f'[{index}/{len(rows)}] {Path(row["file"]).name}: '
                          f'{sum(any(t["status"]=="TARGET_ENTERED" for t in s["attempts"]) for s in result.get("sites",[]))} synthetic target entries',flush=True)
    counts=collections.Counter(t['status'] for result in results for site in result.get('sites',[])
                               for t in site['attempts'])
    document={'schema_version':1,'summary':{'images':len(results),'attempt_statuses':dict(counts)},
              'results':results}
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(document,indent=2),encoding='utf-8')
        print(document['summary'])
    else:print(json.dumps(document,indent=2))


if __name__=='__main__':main()
