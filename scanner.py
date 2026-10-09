"""Read-only x64 WDM callback-surface triage. No driver loading or device IO."""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path
import pefile
try:
    import z3
except ImportError:
    z3 = None
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

UNKNOWN = ('unknown', 0)
VOLATILE = ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')

def canonical(name):
    aliases = {'eax':'rax','ax':'rax','al':'rax','ah':'rax', 'ebx':'rbx','bx':'rbx','bl':'rbx',
               'ecx':'rcx','cx':'rcx','cl':'rcx','edx':'rdx','dx':'rdx','dl':'rdx',
               'esi':'rsi','si':'rsi','edi':'rdi','di':'rdi','esp':'rsp','sp':'rsp',
               'ebp':'rbp','bp':'rbp'}
    if name.startswith('r') and name[-1:] in ('d','w','b') and name[1:-1].isdigit():
        return name[:-1]
    return aliases.get(name, name)

class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.raw = self.path.read_bytes()
        self.pe = pefile.PE(data=self.raw, fast_load=False)
        if self.pe.FILE_HEADER.Machine != 0x8664 or self.pe.OPTIONAL_HEADER.Magic != 0x20b:
            raise ValueError('Only AMD64 PE32+ images are supported')
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64); self.cs.detail = True
        self.imports = {}
        for desc in getattr(self.pe, 'DIRECTORY_ENTRY_IMPORT', []):
            for imp in desc.imports:
                self.imports[imp.address] = (imp.name or b'ordinal').decode(errors='replace')
        self.functions = {}
        runtime_entries = []
        for item in getattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION', []):
            self.functions[self.base + item.struct.BeginAddress] = self.base + item.struct.EndAddress
            runtime_entries.append(item)
        self.fragment_owner = {}
        self.fragment_groups = collections.defaultdict(list)
        direct_parent = {}
        for item in runtime_entries:
            start = self.base + item.struct.BeginAddress
            unwind = getattr(item, 'unwindinfo', None)
            if unwind is not None and getattr(unwind, 'UNW_FLAG_CHAININFO', False):
                parent = getattr(unwind, 'FunctionEntry', None)
                if isinstance(parent, int): direct_parent[start] = self.base + parent
        for start, end in self.functions.items():
            owner = start; ancestors = set()
            while owner in direct_parent and owner not in ancestors:
                ancestors.add(owner); owner = direct_parent[owner]
            self.fragment_owner[start] = owner
            self.fragment_groups[owner].append((start,end))
        self.cache = {}
        self.guards = set()
        self.guard_checks = set()
        config = getattr(getattr(self.pe, 'DIRECTORY_ENTRY_LOAD_CONFIG', None), 'struct', None)
        if config:
            for name in ('GuardCFCheckFunctionPointer', 'GuardCFDispatchFunctionPointer'):
                value = getattr(config, name, 0)
                if value: self.guards.add(value)
                if value and name=='GuardCFCheckFunctionPointer': self.guard_checks.add(value)

    def section(self, va):
        for s in self.pe.sections:
            if self.base + s.VirtualAddress <= va < self.base + s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s
        return None

    def writable(self, va):
        s = self.section(va)
        return bool(s and s.Characteristics & 0x80000000 and not s.Characteristics & 0x20000000)

    def executable(self, va):
        s = self.section(va)
        return bool(s and s.Characteristics & 0x20000000)

    def pointer(self, va):
        try:
            b = self.pe.get_data(va - self.base, 8)
            return struct.unpack('<Q', b)[0] if len(b) == 8 else 0
        except (pefile.PEFormatError, struct.error):
            return 0

    def instructions(self, start):
        if start not in self.cache:
            owner = self.fragment_owner.get(start)
            if owner is not None:
                decoded = {}
                for begin,end in self.fragment_groups[owner]:
                    data = self.pe.get_data(begin - self.base, end - begin)
                    decoded.update((i.address,i) for i in self.cs.disasm(data, begin))
                self.cache[start] = decoded
            else:
                s = self.section(start)
                if not s or not self.executable(start): return {}
                # Leaf/thunk fallback is deliberately bounded and reported.
                end = min(start + 512, self.base + s.VirtualAddress + s.SizeOfRawData)
                data = self.pe.get_data(start - self.base, end - start)
                self.cache[start] = {i.address:i for i in self.cs.disasm(data, start)}
        return self.cache[start]

class Analyzer:
    def __init__(self, image, budget=12000, depth=5):
        self.im = image; self.budget = budget; self.max_depth = depth
        self.dispatch = collections.defaultdict(set)
        self.global_values = {}
        self.findings = {}; self.suspects = {}; self.reachable_slots = {}; self.api_calls = set()
        self.limitations = set(); self.steps = 0
        self.phase = 'initialization'
        self.dispatch_major = 14

    def reg(self, ins, op): return canonical(ins.reg_name(op.reg))

    def cfg_dispatch_thunk(self, address):
        if not self.im.executable(address): return False
        first = self.im.instructions(address).get(address)
        if first is None or first.mnemonic != 'jmp' or len(first.operands) != 1: return False
        operand = first.operands[0]
        if operand.type != X86_OP_MEM or first.reg_name(operand.mem.base) != 'rip': return False
        slot = first.address + first.size + operand.mem.disp
        return slot in self.im.guards and slot not in self.im.guard_checks

    def address(self, ins, op, regs):
        m = op.mem
        if m.base and ins.reg_name(m.base) == 'rip':
            return ('va', ins.address + ins.size + m.disp)
        base = regs.get(canonical(ins.reg_name(m.base)), UNKNOWN) if m.base else ('const',0)
        delta = m.disp
        if m.index:
            index = regs.get(canonical(ins.reg_name(m.index)), UNKNOWN)
            if index[0] != 'const': return UNKNOWN
            delta += index[1] * m.scale
        if base[0] in ('va','stack','driver','irp','iostack','buffer','const'):
            return (base[0], base[1] + delta)
        return UNKNOWN

    def read(self, ins, op, regs, mem):
        if op.type == X86_OP_IMM:
            return ('va' if self.im.section(op.imm) else 'const', op.imm)
        if op.type == X86_OP_REG: return regs.get(self.reg(ins,op), UNKNOWN)
        if op.type != X86_OP_MEM: return UNKNOWN
        # MSVC relative switch tables: movsxd reg,[image_base+index*4+table]; add reg,image_base; jmp reg.
        m=op.mem
        if m.index and m.scale==4 and op.size==4:
            base=regs.get(canonical(ins.reg_name(m.base)),UNKNOWN)
            index=regs.get(canonical(ins.reg_name(m.index)),UNKNOWN)
            bound=regs.get('$bound_'+canonical(ins.reg_name(m.index)),('const',127))
            if base[0]=='va' and index[0]!='const':
                entries=[]
                for k in range(min(bound[1]+1,128)):
                    try:
                        data=self.im.pe.get_data(base[1]+m.disp+k*4-self.im.base,4)
                        entry=struct.unpack('<i',data)[0]
                    except (struct.error,pefile.PEFormatError): break
                    if not self.im.executable(base[1]+entry): break
                    entries.append(entry)
                if entries:
                    self.limitations.add('switch_table_targets_overapproximated')
                    return ('relative_targets',tuple(entries))
        addr = self.address(ins,op,regs)
        if op.size==16 and addr[0] in ('stack','va'):
            lanes=[]
            for delta in (0,8):
                lane=(addr[0],addr[1]+delta)
                if lane in mem: lanes.append(mem[lane])
                elif lane[0]=='va':
                    ptr=self.im.pointer(lane[1])
                    lanes.append(('va',ptr) if self.im.executable(ptr) else UNKNOWN)
                else: lanes.append(UNKNOWN)
            return ('vector',tuple(lanes))
        if addr in mem: return mem[addr]
        if addr == ('irp', 0x18): return ('buffer',0)
        if addr == ('irp', 0xb8): return ('iostack',0)
        if addr[0] == 'iostack':
            if addr[1] == 0 and self.phase == 'dispatch' and op.size == 1: return ('const',self.dispatch_major)
            if addr[1] == 0x18: return ('ioctl',0)
            if addr[1] == 0x10: return ('input_length',0)
            if addr[1] == 8: return ('output_length',0)
        if addr[0] == 'buffer': return ('buffer_data',addr[1])
        if addr[0] == 'va':
            va = addr[1]
            if va in self.im.imports: return ('import', va)
            if va in self.im.guard_checks: return ('guard_check', va)
            if va in self.im.guards: return ('guard', va)
            if self.im.writable(va) and op.size == 8:
                return ('slot', va)
            if va in self.global_values: return self.global_values[va]
            ptr = self.im.pointer(va)
            if op.size == 8 and self.im.executable(ptr): return ('va',ptr)
        return UNKNOWN

    def write(self, ins, op, value, regs, mem):
        if op.type == X86_OP_REG:
            if op.size<8 and value[0] in ('va','stack','driver','irp','iostack','buffer','slot','import','guard','guard_check'):
                value=UNKNOWN
                self.limitations.add('pointer_truncated_to_partial_register')
            regs[self.reg(ins,op)] = value
        elif op.type == X86_OP_MEM:
            addr = self.address(ins,op,regs)
            if addr != UNKNOWN:
                mem[addr] = value
                if value[0]=='vector':
                    for index,lane in enumerate(value[1]):
                        destination=(addr[0],addr[1]+8*index)
                        mem[destination]=lane
                        if self.phase=='initialization' and destination[0]=='driver' and lane[0]=='va':
                            offset=destination[1]-0x70
                            if 0<=offset<=0xd8 and offset%8==0: self.dispatch[offset//8].add(lane[1])
                if self.phase == 'initialization' and addr[0] == 'driver' and value[0] == 'va':
                    offset = addr[1] - 0x70
                    if 0 <= offset <= 0xd8 and offset % 8 == 0:
                        self.dispatch[offset // 8].add(value[1])
                if self.phase == 'initialization' and addr[0] == 'va' and self.im.writable(addr[1]):
                    self.global_values[addr[1]] = value

    def indirect(self, ins, target, regs, trace):
        if target[0] == 'guard': target = regs.get('rax',UNKNOWN)
        if target[0] != 'slot': return
        slot = target[1]
        args = {r:regs.get(r,UNKNOWN) for r in ('rcx','rdx','r8','r9')}
        tainted = {r:v for r,v in args.items() if v[0] in ('buffer','buffer_data')}
        s = self.im.section(slot)
        rec = {'dispatch_rva':hex(trace[0]-self.im.base), 'call_rva':hex(ins.address-self.im.base),
               'slot_rva':hex(slot-self.im.base), 'section':s.Name.rstrip(b'\0').decode(errors='replace'),
               'initial_target_rva':hex(self.im.pointer(slot)-self.im.base) if self.im.executable(self.im.pointer(slot)) else None,
               'arguments':{r:{'kind':v[0],'offset':v[1]} for r,v in args.items()},
               'call_chain_rvas':[hex(x-self.im.base) for x in trace],
               'instruction':f'{ins.mnemonic} {ins.op_str}',
               'interpretation':'Abstract may-path; branch satisfiability and successful completion not proved.'}
        key = (trace[0], ins.address, slot)
        broad_feasibility = self.feasibility(regs.get('$path', ()), require_input=False)
        if broad_feasibility['status'] != 'UNSAT':
            broad_record = dict(rec)
            broad_record['modeled_path_feasibility'] = broad_feasibility
            broad_record['variant'] = 'REACHABLE_WRITABLE_IMAGE_SLOT'
            broad_record['input_argument_required'] = False
            self.reachable_slots[key] = broad_record
        if tainted:
            feasibility = self.feasibility(regs.get('$path', ()))
            if feasibility['status'] == 'UNSAT': return
            rec['modeled_path_feasibility'] = feasibility
            rec['systembuffer_arguments'] = list(tainted)
            self.findings[key] = rec
        else:
            self.suspects[key] = rec

    def feasibility(self, predicates, require_input=True):
        if z3 is None: return {'status':'NOT_CHECKED', 'reason':'z3-solver unavailable'}
        solver=z3.Solver(); solver.set(timeout=1000)
        variables={}
        def value(v,width):
            if v[0]=='const': return z3.BitVecVal(v[1],width)
            if v[0]=='buffer' and v[1]==0:
                pointer=variables.setdefault('systembuffer_pointer_64',z3.BitVec('systembuffer_pointer_64',64))
                return pointer if width==64 else z3.Extract(width-1,0,pointer)
            if v[0] in ('ioctl','input_length','output_length','buffer_data'):
                natural_width=32 if v[0]!='buffer_data' else width
                name=f'{v[0]}_{v[1]}_{natural_width}'
                if name not in variables: variables[name]=z3.BitVec(name,natural_width)
                result=variables[name]
                return z3.ZeroExt(width-natural_width,result) if width>natural_width else z3.Extract(width-1,0,result) if width<natural_width else result
            return None
        used=0
        for branch, comparison, taken in predicates:
            mn,a,b,width=comparison
            av=value(a,width); bv=value(b,width)
            if av is None or bv is None: continue
            diff=av-bv if mn=='cmp' else av&bv
            z=diff==0; c=z3.ULT(av,bv) if mn=='cmp' else z3.BoolVal(False)
            signed_less=av<bv if mn=='cmp' else diff<0
            signed_greater=av>bv if mn=='cmp' else diff>0
            conditions={'je':z,'jz':z,'jne':z3.Not(z),'jnz':z3.Not(z),'jb':c,'jc':c,
                        'jae':z3.Not(c),'jnb':z3.Not(c),'ja':z3.And(z3.Not(c),z3.Not(z)),
                        'jbe':z3.Or(c,z),'jl':signed_less,'jge':z3.Not(signed_less),
                        'jle':z3.Or(z,signed_less),'jg':signed_greater,'js':diff<0,'jns':diff>=0}
            condition=conditions.get(branch)
            if condition is not None:
                solver.add(condition if taken else z3.Not(condition)); used+=1
        # Exact variant needs nonempty input and a SystemBuffer-bearing method.
        # Broad callback reachability allows any valid DeviceIoControl request.
        ioctl=variables.setdefault('ioctl_0_32',z3.BitVec('ioctl_0_32',32))
        if require_input:
            length=variables.setdefault('input_length_0_32',z3.BitVec('input_length_0_32',32))
            pointer=variables.setdefault('systembuffer_pointer_64',z3.BitVec('systembuffer_pointer_64',64))
            solver.add(ioctl & 3 != 3, z3.UGT(length,0), pointer != 0)
        status=solver.check()
        if status==z3.unsat: return {'status':'UNSAT'}
        if status!=z3.sat: return {'status':'UNKNOWN','reason':solver.reason_unknown()}
        model=solver.model()
        return {'status':'SAT_PARTIAL_MODEL','modeled_predicates':used,
                'witness':{k:hex(model.eval(v,model_completion=True).as_long()) for k,v in variables.items()},
                'scope':'Only tracked integer predicates; not proof of runtime reachability, handle access, or full buffer validity.'}

    def walk(self, start, initial, initial_mem=None, trace=None):
        self.return_effects={}
        trace = trace or [start]
        code = self.im.instructions(start)
        if not code: self.limitations.add('unresolved_code_target'); return UNKNOWN
        if start not in self.im.functions: self.limitations.add('bounded_leaf_or_thunk_decode')
        queue = collections.deque([(start,dict(initial),dict(initial_mem or {}))])
        seen = set(); returns = set(); visits=collections.Counter(); completed=[]
        terminated=0; abandoned=0
        while queue:
            pc, regs, mem = queue.popleft()
            while pc in code:
                signature = (pc,tuple(sorted(regs.items())),tuple(sorted(mem.items())))
                if signature in seen: break
                seen.add(signature)
                visits[pc]+=1
                if visits[pc]>32:
                    self.limitations.add('per_instruction_state_limit'); abandoned+=1; break
                self.steps += 1
                if self.steps > self.budget:
                    self.limitations.add('instruction_state_budget_exhausted'); self.return_effects={}; return UNKNOWN
                ins = code[pc]; ops = ins.operands; nxt = pc + ins.size; mn = ins.mnemonic
                if mn in ('cmp','test') and len(ops)==2:
                    a=self.read(ins,ops[0],regs,mem); b=self.read(ins,ops[1],regs,mem)
                    regs['$comparison']=(mn,a,b,ops[0].size*8)
                    if mn=='cmp' and ops[0].type==X86_OP_REG and b[0]=='const' and 0<=b[1]<128:
                        regs['$bound_'+self.reg(ins,ops[0])]=b
                    if a[0]=='const' and b[0]=='const':
                        mask=(1 << (ops[0].size*8))-1
                        av=a[1]&mask; bv=b[1]&mask
                        result=(av-bv if mn=='cmp' else av&bv)&mask
                        sign=1 << (ops[0].size*8-1)
                        regs['$zf']=('const',int(result==0))
                        regs['$cf']=('const',int(av<bv) if mn=='cmp' else 0)
                        regs['$sf']=('const',int(bool(result&sign)))
                        regs['$of']=('const',int(bool((av^bv)&(av^result)&sign)) if mn=='cmp' else 0)
                    else:
                        for f in ('$zf','$cf','$sf','$of'): regs[f]=UNKNOWN
                    pc=nxt; continue
                if mn in ('mov','movabs','movzx','movsx','movsxd','movups','movaps','movdqu','movdqa','movq','movsd') and len(ops)==2:
                    self.write(ins,ops[0],self.read(ins,ops[1],regs,mem),regs,mem)
                elif mn.startswith('rep stos') and len(ops)>=2:
                    count=regs.get('rcx',UNKNOWN); destination=regs.get('rdi',UNKNOWN)
                    value=regs.get('rax',UNKNOWN); width=ops[0].size
                    if count[0]=='const' and 0 <= count[1] <= 512 and destination[0] in ('driver','stack','va'):
                        for index in range(count[1]):
                            regs['rdi']=(destination[0],destination[1]+index*width)
                            self.write(ins,ops[0],value,regs,mem)
                        regs['rdi']=(destination[0],destination[1]+count[1]*width)
                        regs['rcx']=('const',0)
                    else:
                        self.limitations.add('unresolved_bulk_store')
                        regs['rdi']=UNKNOWN; regs['rcx']=UNKNOWN
                elif mn == 'lea' and len(ops)==2:
                    self.write(ins,ops[0],self.address(ins,ops[1],regs),regs,mem)
                elif mn == 'push':
                    sp = regs.get('rsp',('stack',0)); sp = ('stack',sp[1]-8)
                    value = self.read(ins,ops[0],regs,mem); regs['rsp']=sp; mem[sp]=value
                elif mn == 'pop':
                    sp=regs.get('rsp',('stack',0)); self.write(ins,ops[0],mem.get(sp,UNKNOWN),regs,mem); regs['rsp']=('stack',sp[1]+8)
                elif mn in ('add','sub') and len(ops)==2:
                    a=self.read(ins,ops[0],regs,mem); b=self.read(ins,ops[1],regs,mem)
                    value=(a[0],a[1]+(b[1] if mn=='add' else -b[1])) if b[0]=='const' and a[0] in ('const','va','stack','irp','driver','iostack','buffer') else UNKNOWN
                    if mn=='add' and a[0]=='relative_targets' and b[0]=='va': value=('targets',tuple(b[1]+x for x in a[1]))
                    self.write(ins,ops[0],value,regs,mem)
                elif mn == 'xor' and len(ops)==2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG and ops[0].reg==ops[1].reg:
                    self.write(ins,ops[0],('const',0),regs,mem)
                elif mn in ('call','jmp'):
                    if mn=='call' and ops[0].type==X86_OP_IMM and self.cfg_dispatch_thunk(ops[0].imm):
                        target=regs.get('rax',UNKNOWN)
                    else:
                        target=self.read(ins,ops[0],regs,mem)
                    if target[0]=='guard_check':
                        # A check validates a target; only guard dispatch invokes it.
                        for f in ('$zf','$cf','$sf','$of'): regs[f]=UNKNOWN
                        regs.pop('$comparison',None)
                        if mn=='jmp': returns.add(regs.get('rax',UNKNOWN)); completed.append(dict(mem)); break
                        pc=nxt; continue
                    if mn=='jmp' and target[0]=='targets':
                        for destination in target[1]:
                            if destination in code: queue.append((destination,dict(regs),dict(mem)))
                            else: abandoned+=1; self.limitations.add('unresolved_switch_destination')
                        break
                    if self.phase == 'dispatch': self.indirect(ins,target,regs,trace)
                    result=UNKNOWN
                    if target[0]=='import':
                        api=self.im.imports[target[1]]; self.api_calls.add(api)
                        if api in ('KeBugCheck','KeBugCheckEx'):
                            terminated+=1; break
                        if api=='IoGetCurrentIrpStackLocation' and regs.get('rcx')==('irp',0): result=('iostack',0)
                    elif target[0]=='va' and target[1] in code and mn=='jmp':
                        pc=target[1]; continue
                    elif target[0]=='va' and self.im.executable(target[1]):
                        if len(trace) >= self.max_depth or target[1] in trace:
                            self.limitations.add('call_depth_or_recursion_limit')
                        else:
                            child=dict(regs); child['rsp']=('stack',regs.get('rsp',('stack',0))[1]-8)
                            result=self.walk(target[1],child,mem,trace+[target[1]])
                            mem.update(self.return_effects)
                            if result[0]=='noreturn': terminated+=1; break
                    elif target[0] not in ('import','guard','slot'):
                        self.limitations.add('unresolved_indirect_control_flow')
                    if mn=='jmp': returns.add(result); completed.append(dict(mem)); break
                    for r in VOLATILE: regs[r]=UNKNOWN
                    for f in ('$zf','$cf','$sf','$of'): regs[f]=UNKNOWN
                    regs.pop('$comparison',None)
                    regs['rax']=result
                elif mn.startswith('j') or mn.startswith('loop'):
                    flags=[regs.get(f,UNKNOWN) for f in ('$zf','$cf','$sf','$of')]
                    decision=None
                    if all(v[0]=='const' for v in flags):
                        z,c,s,o=[v[1] for v in flags]
                        conditions={'je':z,'jz':z,'jne':not z,'jnz':not z,'jb':c,'jc':c,'jae':not c,'jnb':not c,
                                    'ja':not c and not z,'jbe':c or z,'jl':s!=o,'jge':s==o,'jle':z or s!=o,'jg':not z and s==o,
                                    'js':s,'jns':not s,'jo':o,'jno':not o}
                        decision=conditions.get(mn)
                    if ops and ops[0].type==X86_OP_IMM and ops[0].imm in code:
                        if decision is not False and decision != 0:
                            branch_regs=dict(regs)
                            comparison=regs.get('$comparison')
                            if comparison and decision is None:
                                branch_regs['$path']=tuple(sorted(set(regs.get('$path',())+((mn,comparison,True),))))
                            queue.append((ops[0].imm,branch_regs,dict(mem)))
                    else: self.limitations.add('unresolved_branch'); abandoned+=1
                    if decision is True or decision == 1: break
                    comparison=regs.get('$comparison')
                    if comparison and decision is None:
                        regs['$path']=tuple(sorted(set(regs.get('$path',())+((mn,comparison,False),))))
                elif mn.startswith('ret'):
                    returns.add(regs.get('rax',UNKNOWN)); completed.append(dict(mem)); break
                elif mn in ('int3','ud2','hlt','int'):
                    if mn=='int' and ops and ops[0].imm==0x29: terminated+=1
                    elif mn in ('ud2','hlt'): terminated+=1
                    else: abandoned+=1; self.limitations.add('interrupt_or_exception_semantics_not_modeled')
                    break
                else:
                    for op in ops:
                        if op.access & CS_AC_WRITE:
                            self.write(ins,op,UNKNOWN,regs,mem)
                # Only CMP/TEST flag predicates are currently modeled. Never reuse stale flags.
                if mn in ('add','sub','xor','and','or','inc','dec','shl','shr','sar','neg','imul'):
                    for f in ('$zf','$cf','$sf','$of'): regs[f]=UNKNOWN
                    regs.pop('$comparison',None)
                pc=nxt
                if pc not in code:
                    abandoned+=1; self.limitations.add('fallthrough_outside_decoded_function')
        self.return_effects={}
        if completed:
            caller_boundary=initial.get('rsp',('stack',0))[1]+8
            keys=set().union(*(m.keys() for m in completed))
            for key in keys:
                if key[0]=='stack' and key[1]<caller_boundary: continue
                values={m.get(key,UNKNOWN) for m in completed}
                self.return_effects[key]=next(iter(values)) if len(values)==1 else UNKNOWN
        if not completed and terminated and not abandoned: return ('noreturn',0)
        return next(iter(returns)) if len(returns)==1 else UNKNOWN

    def run(self, engine='legacy', emulate_init=False, flow_budget=50000):
        self.walk(self.im.entry, {'rcx':('driver',0),'rdx':('registry',0),'rsp':('stack',0)})
        init_steps=self.steps
        init_limitations=sorted(self.limitations)
        abstract_roots=set(self.dispatch.get(0xe,()))
        emulation=None
        synthetic_roots=set()
        if emulate_init:
            if len(self.im.raw)>64*1024*1024:
                emulation={'status':'IMAGE_SIZE_LIMIT','device_control_dispatch_rvas':[],
                           'model':'Synthetic offline initialization skipped above 64 MiB.'}
            else:
                from init_emulator import emulate_registration
                emulation=emulate_registration(self.im)
                synthetic_roots={self.im.base+int(x,0) for x in emulation['device_control_dispatch_rvas']}
                self.dispatch[0xe].update(synthetic_roots)
                self.dispatch[0].update(self.im.base+int(x,0) for x in emulation['create_dispatch_rvas'])
        fixed_init=None
        fixed_init_roots=set()
        if engine in ('fixedpoint','both') and not self.dispatch.get(0xe) and len(self.im.raw)<=64*1024*1024:
            names=set(self.im.imports.values())
            if names & {'IoCreateDevice','IoCreateDeviceSecure','WdmlibIoCreateDeviceSecure'}:
                from init_flow import analyze_initialization
                fixed_init=analyze_initialization(self.im,min(flow_budget,30000))
                fixed_init_roots={self.im.base+int(x,0) for x in fixed_init['device_control_dispatch_rvas']}
                self.dispatch[0xe].update(fixed_init_roots)
                self.dispatch[0].update(self.im.base+int(x,0) for x in fixed_init['create_dispatch_rvas'])
        flow=None
        if engine in ('legacy','both'):
            self.phase='dispatch'
            for target in sorted(self.dispatch.get(0xe,())):
                self.steps=0
                self.walk(target, {'rcx':('device',0),'rdx':('irp',0),'rsp':('stack',0)})
        if engine in ('fixedpoint','both'):
            from flow_engine import analyze_dispatch
            flow=analyze_dispatch(self.im,self.dispatch.get(0xe,()),flow_budget)
            for finding in flow['findings']:
                key=(finding.get('dispatch_rva'),finding.get('call_rva'),finding.get('slot_rva'))
                self.findings[key]=finding
            for finding in flow['unproven_writable_indirect_calls']:
                key=(finding.get('dispatch_rva'),finding.get('call_rva'),finding.get('slot_rva'))
                self.suspects[key]=finding
            self.limitations.update(flow['limitations'])
        wdf_registration=None
        wdf_flow=None
        if engine in ('fixedpoint','both') and 'WdfVersionBind' in self.im.imports.values():
            from wdf_probe import discover_wdf_io_control
            wdf_registration=discover_wdf_io_control(self.im)
            wdf_roots={self.im.base+int(rva,0) for rva in wdf_registration['roots_rvas']}
            if wdf_roots:
                from wdf_flow import analyze_wdf_callbacks
                wdf_flow=analyze_wdf_callbacks(self.im,wdf_roots,min(flow_budget,30000))
                for finding in wdf_flow['findings']:
                    key=('wdf',finding.get('dispatch_rva'),finding.get('call_rva'),finding.get('slot_rva'))
                    self.findings[key]=finding
                for finding in wdf_flow['unproven_writable_indirect_calls']:
                    key=('wdf',finding.get('dispatch_rva'),finding.get('call_rva'),finding.get('slot_rva'))
                    self.suspects[key]=finding
        has_dispatch=bool(self.dispatch.get(0xe))
        if not has_dispatch: self.limitations.add('device_control_dispatch_not_resolved')
        imports=set(self.im.imports.values())
        namespace=sorted(imports & {'IoCreateDevice','IoCreateDeviceSecure','IoCreateSymbolicLink','IoRegisterDeviceInterface','IoSetDeviceInterfaceState'})
        strings=[]
        # These are hints only: dead strings and unreachable imports exist in real images.
        import re
        for match in re.finditer(rb'(?:[\x20-\x7e]\x00){8,}',self.im.raw):
            value=match.group().decode('utf-16le')
            if value.startswith(('\\Device\\','\\DosDevices\\','\\??\\')): strings.append(value)
        modeled_roots=bool(self.dispatch.get(0xe)) or bool(wdf_registration and wdf_registration['roots_rvas'])
        modeled_complete=bool((flow and flow['coverage']['complete'] and self.dispatch.get(0xe)) or
                              (wdf_flow and wdf_flow['coverage']['complete']))
        classification=('PATTERN_CANDIDATE' if self.findings else
                        'NO_CANDIDATE_IN_MODELED_PATHS' if modeled_roots and modeled_complete else
                        'INCONCLUSIVE')
        return {'schema_version':3,'file':str(self.im.path.resolve()),'sha256':hashlib.sha256(self.im.raw).hexdigest(),
                'classification':classification,
                'classification_scope':'Only the bounded, modeled dispatch/callback graph; not a proof of driver-wide absence or user accessibility.',
                'vulnerability_claim':False,'user_openability':'UNCONFIRMED_REQUIRES_RUNTIME_AND_DEPLOYMENT_SECURITY',
                'namespace_import_hints':namespace,'namespace_string_hints':sorted(set(strings)),
                'create_dispatch_rvas':[hex(x-self.im.base) for x in sorted(self.dispatch.get(0,()))],
                'device_control_dispatch_rvas':[hex(x-self.im.base) for x in sorted(self.dispatch.get(0xe,()))],
                'findings':list(self.findings.values()),'unproven_writable_indirect_calls':list(self.suspects.values()),
                'path_refined_writable_indirect_calls':list(self.reachable_slots.values()),
                'limitations':sorted(self.limitations),'initialization_limitations':init_limitations,
                'initialization_states_processed':init_steps,
                'dispatch_root_provenance':{'abstract_initialization_rvas':[hex(x-self.im.base) for x in sorted(abstract_roots)],
                                            'synthetic_execution_rvas':[hex(x-self.im.base) for x in sorted(synthetic_roots)],
                                            'fixed_point_initialization_rvas':[hex(x-self.im.base) for x in sorted(fixed_init_roots)]},
                'synthetic_initialization':emulation,'fixed_point_initialization':fixed_init,
                'fixed_point_analysis':flow,'wdf_callback_registration':wdf_registration,
                'wdf_callback_analysis':wdf_flow,
                'analysis_engine':engine,
                'analysis_model':'x64 WDM offsets; abstract initialization, optional synthetic Unicorn path, bounded legacy or finite MAY dispatch analysis'}

def callback_census(im, function_starts=None):
    """Independent structural survey; no IRP type/reachability claim from these sites."""
    sites={}
    for start in sorted(im.functions if function_starts is None else function_starts):
        tracked={}
        for ins in im.instructions(start).values():
            ops=ins.operands
            if ins.mnemonic in ('call','jmp') and ops:
                target=None; guard=False
                if ops[0].type==X86_OP_REG:
                    target=tracked.get(canonical(ins.reg_name(ops[0].reg)))
                elif ops[0].type==X86_OP_MEM and ins.reg_name(ops[0].mem.base)=='rip':
                    va=ins.address+ins.size+ops[0].mem.disp
                    if va in im.guard_checks:
                        pass
                    elif va in im.guards:
                        target=tracked.get('rax'); guard=True
                    elif im.writable(va) and va not in im.imports: target=va
                if target:
                    sites[(ins.address,target)]={'function_rva':hex(start-im.base),'call_rva':hex(ins.address-im.base),
                        'slot_rva':hex(target-im.base),'cfg_guard_dispatch':guard,
                        'meaning':'Structural writable-slot call only; IRP provenance and user reachability unproved.'}
                if ins.mnemonic=='call':
                    for r in VOLATILE: tracked.pop(r,None)
                else: tracked.clear()
                continue
            value=None
            if ins.mnemonic=='mov' and len(ops)==2 and ops[0].type==X86_OP_REG:
                source=ops[1]
                if source.type==X86_OP_MEM and source.size==8 and ins.reg_name(source.mem.base)=='rip':
                    va=ins.address+ins.size+source.mem.disp
                    if im.writable(va) and va not in im.imports: value=va
                elif source.type==X86_OP_REG: value=tracked.get(canonical(ins.reg_name(source.reg)))
            for op in ops:
                if op.type==X86_OP_REG and op.access & CS_AC_WRITE:
                    tracked.pop(canonical(ins.reg_name(op.reg)),None)
            if value is not None: tracked[canonical(ins.reg_name(ops[0].reg))]=value
            if ins.mnemonic.startswith('j') or ins.mnemonic.startswith('ret'): tracked.clear()
        # Do not retain whole-driver disassembly (GPU drivers can be enormous).
        im.cache.pop(start,None)
    return list(sites.values())

def scan(path, budget=12000, depth=5, census=False, census_function_rvas=None,
         engine='legacy', emulate_init=False, flow_budget=50000):
    try:
        im=Image(path); report=Analyzer(im,budget,depth).run(engine,emulate_init,flow_budget)
        if census:
            starts=None if census_function_rvas is None else {im.base+int(rva,0) for rva in census_function_rvas}
            report['structural_callback_sites']=callback_census(im,starts)
        return report
    except Exception as exc:
        return {'file':str(Path(path).resolve()),'classification':'ERROR','error':f'{type(exc).__name__}: {exc}'}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('paths',nargs='+',type=Path)
    p.add_argument('--recursive',action='store_true')
    p.add_argument('--output',type=Path,help='Write JSON report to this file; omit to print JSON to stdout')
    p.add_argument('--budget',type=int,default=12000)
    p.add_argument('--depth',type=int,default=5)
    p.add_argument('--census',action='store_true',help='Survey all unwind-described functions for additional unanchored writable callback sites')
    p.add_argument('--engine',choices=('fixedpoint','legacy','both'),default='fixedpoint')
    p.add_argument('--emulate-init',action='store_true',help='Run a copied image under synthetic Unicorn kernel import models')
    p.add_argument('--flow-budget',type=int,default=50000)
    p.add_argument('--offline-validate',action='store_true',
                   help='Add broad variant inventory and bounded synthetic Unicorn request replay; never opens a device')
    p.add_argument('--offline-max-sites',type=int,default=12,
                   help='Maximum prioritized indirect-call sites to emulate per image')
    p.add_argument('--offline-instruction-limit',type=int,default=30000)
    a=p.parse_args()
    if a.offline_max_sites<1 or a.offline_instruction_limit<1:
        p.error('offline budgets must be positive')
    files=[]
    for path in a.paths:
        files.extend(sorted(path.rglob('*.sys') if a.recursive else path.glob('*.sys')) if path.is_dir() else [path])
    results=[]
    for n,path in enumerate(dict.fromkeys(files),1):
        result=scan(path,a.budget,a.depth,a.census,engine=a.engine,
                    emulate_init=a.emulate_init,flow_budget=a.flow_budget); results.append(result)
        if a.offline_validate and result['classification']!='ERROR':
            try:
                from user_interaction_scan import analyze_one
                from offline_validation import validate_row
                broad=analyze_one(result,init_budget=min(a.flow_budget,30000),
                                  flow_budget=min(a.flow_budget,30000))
                result['user_interaction_analysis']=broad
                result['offline_validation']=validate_row(
                    broad,max_sites=a.offline_max_sites,
                    instruction_limit=a.offline_instruction_limit)
            except Exception as exc:
                result['offline_validation']={'status':'ERROR',
                    'error':f'{type(exc).__name__}: {exc}',
                    'no_live_reachability_claim':True}
        if a.output:
            print(f"[{n}/{len(files)}] {path.name}: {result['classification']}",flush=True)
    document={'results':results,'summary':dict(collections.Counter(r['classification'] for r in results))}
    if a.output:
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(document,indent=2),encoding='utf-8')
        print(json.dumps(document['summary']))
    else:
        print(json.dumps(document,indent=2))

if __name__=='__main__': main()
