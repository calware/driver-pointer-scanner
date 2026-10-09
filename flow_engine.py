"""Dispatch-rooted finite MAY dataflow; offline image reads only.

Every branch is joined. Findings are candidates, never runtime witnesses. Finite
kind/offset widening guarantees loops converge without dropping queued paths.
"""
from collections import deque, defaultdict
from capstone import CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

UNKNOWN = frozenset({('unknown', None)})
VOLATILE = ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11')
POINTERS = {'va', 'stack', 'irp', 'iostack', 'buffer', 'device', 'driver', 'registry', 'slot', 'readonly_slot', 'image_table_slot', 'import', 'guard', 'guard_check'}
MAX_ALTERNATIVES = 8
MAX_MEMORY = 128


def canonical(name):
    aliases = {'eax':'rax','ax':'rax','al':'rax','ah':'rax','ebx':'rbx','bx':'rbx','bl':'rbx',
               'ecx':'rcx','cx':'rcx','cl':'rcx','edx':'rdx','dx':'rdx','dl':'rdx',
               'esi':'rsi','si':'rsi','sil':'rsi','edi':'rdi','di':'rdi','dil':'rdi',
               'esp':'rsp','sp':'rsp','spl':'rsp','ebp':'rbp','bp':'rbp','bpl':'rbp'}
    if name.startswith('r') and name[-1:] in ('d','w','b') and name[1:-1].isdigit():
        return name[:-1]
    return aliases.get(name, name)


def value(kind, offset=0):
    return frozenset({(kind, offset)})


def join_values(*values):
    """Kind-preserving finite union. None offsets subsume all offsets of a kind."""
    atoms = set().union(*values)
    kinds = defaultdict(set)
    for kind, offset in atoms:
        kinds[kind].add(offset)
    result = set()
    for kind, offsets in kinds.items():
        if None in offsets or (len(offsets) > MAX_ALTERNATIVES and kind not in ('relative_target','code_target')):
            result.add((kind, None))
        else:
            result.update((kind, offset) for offset in offsets)
    return frozenset(result)


def join_state(old, new):
    if old is None:
        return dict(new), True
    result = dict(old)
    for key in old.keys() | new.keys():
        # Absence is unknown, including spills only written on one predecessor.
        result[key] = join_values(old.get(key, UNKNOWN), new.get(key, UNKNOWN))
    return result, result != old


class Flow:
    def __init__(self, image, root, budget):
        self.im, self.root, self.budget = image, root, budget
        self.states, self.code, self.summaries = {}, {}, {}
        self.queue, self.queued = deque(), set()
        self.callers = defaultdict(set)
        self.findings, self.suspects, self.nonimage_indirect, self.readonly_image_indirect = {}, {}, {}, {}
        self.limitations = set()
        self.steps = 0
        self.joins = 0
        self.branch_joins = 0
        self.max_queue = 0
        self.memory_keys = set()

    def instructions(self, function):
        if function not in self.code:
            self.code[function] = self.im.instructions(function)
        return self.code[function]

    def enqueue(self, function, address, state):
        if address not in self.instructions(function):
            # Chained unwind fragments may be returned by the image API; fallback
            # discovers a separately described executable fragment when needed.
            fragment = self.im.instructions(address)
            if fragment and address in fragment:
                self.code[function].update(fragment)
            else:
                self.limitations.add('unresolved_control_flow_edge')
                return
        key = (function, address)
        merged, changed = join_state(self.states.get(key), state)
        if changed:
            self.joins += int(key in self.states)
            self.states[key] = merged
            if key not in self.queued:
                self.queue.append(key)
                self.queued.add(key)
            self.max_queue = max(self.max_queue, len(self.queue))

    def reg(self, ins, op):
        return canonical(ins.reg_name(op.reg))

    def address(self, ins, op, state):
        mem = op.mem
        if mem.base and ins.reg_name(mem.base) == 'rip':
            return value('va', ins.address + ins.size + mem.disp)
        bases = state.get(canonical(ins.reg_name(mem.base)), UNKNOWN) if mem.base else value('const', 0)
        indexes = state.get(canonical(ins.reg_name(mem.index)), UNKNOWN) if mem.index else value('const', 0)
        out = []
        for kind, offset in bases:
            for ikind, index in indexes:
                if kind not in POINTERS | {'const'}:
                    out.append(UNKNOWN)
                elif ikind == 'const' and index is not None and offset is not None:
                    out.append(value(kind, offset + mem.disp + index * mem.scale))
                else:
                    out.append(value(kind, None))
        return join_values(*out) if out else UNKNOWN

    def read(self, ins, op, state):
        if op.type == X86_OP_REG:
            return state.get(self.reg(ins, op), UNKNOWN)
        if op.type == X86_OP_IMM:
            return value('va' if self.im.section(op.imm) else 'const', op.imm)
        if op.type != X86_OP_MEM:
            return UNKNOWN
        out = []
        for kind, offset in self.address(ins, op, state):
            # Wildcard aliases must include matching tracked cells and base fields.
            if offset is None:
                out.extend(v for k, v in state.items() if isinstance(k, tuple) and k[0] == kind)
                if kind == 'buffer': out.append(value('buffer_data', None))
                elif kind == 'irp': out.extend((value('buffer'), value('iostack')))
                elif kind == 'iostack': out.extend((value('ioctl'), value('input_length'), value('output_length'), value('major')))
                else: self.limitations.add('imprecise_memory_read')
                out.append(UNKNOWN)
                continue
            key = (kind, offset)
            if key in state: out.append(state[key])
            if (kind,None) in state: out.append(state[(kind,None)])
            if kind == 'irp' and offset == 0x18: out.append(value('buffer'))
            elif kind == 'irp' and offset == 0xb8: out.append(value('iostack'))
            elif kind == 'iostack':
                fields = {0:'major', 8:'output_length', 0x10:'input_length', 0x18:'ioctl'}
                out.append(value(fields[offset]) if offset in fields else UNKNOWN)
            elif kind == 'buffer': out.append(value('buffer_data', offset))
            elif kind == 'va':
                if offset in self.im.guard_checks: out.append(value('guard_check', offset))
                elif offset in self.im.guards: out.append(value('guard', offset))
                elif offset in self.im.imports: out.append(value('import', offset))
                elif self.im.writable(offset) and op.size == 8: out.append(value('slot', offset))
                else:
                    ptr = self.im.pointer(offset)
                    if op.size == 8 and self.im.executable(ptr):
                        out.append(value('va', ptr))
                        out.append(value('readonly_slot', offset))
                    else: out.append(UNKNOWN)
            elif key not in state: out.append(UNKNOWN)
        # Unknown index relative switch-table loads, MSVC style.
        mem = op.mem
        if mem.index and mem.scale in (4, 8):
            bases = state.get(canonical(ins.reg_name(mem.base)), UNKNOWN)
            indexes = state.get(canonical(ins.reg_name(mem.index)), UNKNOWN)
            if any(k != 'const' or x is None for k, x in indexes):
                for kind, base in bases:
                    if kind != 'va' or base is None: continue
                    targets = []
                    for i in range(256):
                        try:
                            import struct
                            data = self.im.pe.get_data(base + mem.disp + i * mem.scale - self.im.base, mem.scale)
                            x = struct.unpack('<i' if mem.scale == 4 else '<Q', data)[0]
                        except (AttributeError, ValueError, struct.error): break
                        if not self.im.executable(base + x if mem.scale == 4 else x): break
                        targets.append(x)
                    if targets:
                        # Branch targets must stay exact; wildcard target is explicitly unresolved.
                        out.append(frozenset(('relative_target' if mem.scale == 4 else 'code_target', x) for x in targets))
                        out.append(value('image_table_slot', base + mem.disp))
                        self.limitations.add('switch_table_bounds_unproved')
                        if len(targets) == 256: self.limitations.add('switch_table_enumeration_limit')
        return join_values(*out) if out else UNKNOWN

    def write(self, ins, op, val, state):
        if op.type == X86_OP_REG:
            if op.size < 8 and any(k in POINTERS for k, _ in val):
                val = join_values(UNKNOWN, frozenset((k, x) for k, x in val if k not in POINTERS))
                self.limitations.add('pointer_truncation')
            if op.size < 4:
                val = join_values(state.get(self.reg(ins, op), UNKNOWN), val)
                self.limitations.add('partial_register_write')
            state[self.reg(ins, op)] = val
        elif op.type == X86_OP_MEM:
            addresses = self.address(ins, op, state)
            for kind, offset in addresses:
                if kind == 'unknown' or offset is None:
                    self.limitations.add('unresolved_memory_write')
                    # Weak update every known possible alias; never silently preserve certainty.
                    for key in list(state):
                        if isinstance(key, tuple) and (kind == 'unknown' or key[0] == kind):
                            state[key] = join_values(state[key], val, UNKNOWN)
                    continue
                key = (kind, offset)
                if key not in self.memory_keys and len(self.memory_keys) >= MAX_MEMORY:
                    self.limitations.add('memory_cells_widened')
                    key = (kind, None)
                self.memory_keys.add(key)
                state[key] = val if len(addresses) == 1 else join_values(state.get(key, UNKNOWN), val)
                if kind == 'va': self.limitations.add('global_write_alias_effects_unmodeled')

    def finding(self, ins, targets, state, function):
        for kind, slot in targets:
            if kind != 'slot': continue
            if slot is None:
                self.limitations.add('callback_slot_address_widened')
                continue
            args = {r:state.get(r, UNKNOWN) for r in ('rcx','rdx','r8','r9')}
            # x64 argument 5 starts at caller RSP+0x20.
            for skind, sp in state.get('rsp', UNKNOWN):
                if skind == 'stack' and sp is not None:
                    for i in range(4):
                        key = ('stack', sp + 0x20 + i * 8)
                        if key in state: args['stack_arg_' + str(i+5)] = state[key]
            tainted = [r for r,v in args.items() if any(k in ('buffer','buffer_data') for k,_ in v)]
            register_tainted = [r for r in tainted if r in ('rcx','rdx','r8','r9')]
            section = self.im.section(slot)
            record = {'dispatch_rva':hex(self.root-self.im.base),'call_rva':hex(ins.address-self.im.base),
                      'function_rva':hex(function-self.im.base),'slot_rva':hex(slot-self.im.base),
                      'section':section.Name.rstrip(b'\0').decode(errors='replace') if section else None,
                      'initial_target_rva':hex(self.im.pointer(slot)-self.im.base) if self.im.executable(self.im.pointer(slot)) else None,
                      'arguments':{r:[{'kind':k,'offset':x} for k,x in sorted(v,key=repr)] for r,v in args.items()},
                      'systembuffer_arguments':tainted,'stack_only_input_lead':bool(tainted and not register_tainted),
                      'instruction':ins.mnemonic+' '+ins.op_str,
                      'modeled_path_feasibility':{'status':'NOT_CHECKED','reason':'MAY joins discard branch predicates'},
                      'interpretation':'Fixed-point MAY candidate; correlated predicates, runtime invocation and successful completion are not proved.'}
            key = (ins.address,slot)
            destination = self.findings if register_tainted else self.suspects
            destination[key] = record
            if register_tainted: self.suspects.pop(key,None)

    def nonimage_call(self, ins, targets, state, function):
        """Record unresolved calls through non-stack object memory fields.

        This is a lower-confidence engineering lead: the call is on a modeled
        root path, but the field's backing allocation and mutability are not
        established from the image alone.
        """
        if not ins.operands or ins.operands[0].type != X86_OP_MEM:
            return
        op = ins.operands[0]
        base_name = ins.reg_name(op.mem.base) if op.mem.base else None
        if not base_name or base_name in ('rip','rsp','rbp'):
            return
        if any(kind in ('import','slot','readonly_slot','guard','guard_check','va','code_target','wdf_api')
               for kind,_ in targets):
            return
        base = state.get(canonical(base_name), UNKNOWN)
        if all(kind == 'stack' for kind,_ in base):
            return
        key = (ins.address, op.mem.disp)
        self.nonimage_indirect[key] = {
            'dispatch_rva': hex(self.root-self.im.base),
            'function_rva': hex(function-self.im.base),
            'call_rva': hex(ins.address-self.im.base),
            'instruction': ins.mnemonic+' '+ins.op_str,
            'base_register': canonical(base_name),
            'field_displacement': op.mem.disp,
            'base_provenance': [{'kind':kind,'offset':offset} for kind,offset in sorted(base,key=repr)],
            'classification': 'NONIMAGE_INDIRECT_CALL_MUTABILITY_UNVERIFIED',
            'runtime_reachability': 'UNVERIFIED'}

    def readonly_image_call(self, ins, targets, function):
        for kind, slot in targets:
            if kind not in ('readonly_slot', 'image_table_slot') or slot is None:
                continue
            section = self.im.section(slot)
            if section is None: continue
            target = self.im.pointer(slot)
            if kind == 'readonly_slot' and not self.im.executable(target): continue
            key = (ins.address, slot)
            self.readonly_image_indirect[key] = {
                'dispatch_rva': hex(self.root-self.im.base),
                'function_rva': hex(function-self.im.base),
                'call_rva': hex(ins.address-self.im.base),
                'slot_rva': hex(slot-self.im.base),
                'initial_target_rva': hex(target-self.im.base) if self.im.executable(target) else None,
                'section': section.Name.rstrip(b'\0').decode(errors='replace'),
                'storage': 'IMAGE_POINTER_TABLE' if kind == 'image_table_slot' else 'READ_ONLY_IMAGE_SECTION',
                'instruction': ins.mnemonic+' '+ins.op_str,
                'runtime_reachability': 'UNVERIFIED'}

    def continuation(self, function, ins, state, result=UNKNOWN):
        nextstate = dict(state)
        for reg in VOLATILE: nextstate[reg] = UNKNOWN
        nextstate['rax'] = result
        self.enqueue(function, ins.address+ins.size, nextstate)

    def cfg_dispatch_thunk(self, address):
        """Recognize the shared MSVC guard-dispatch jump through load config."""
        if not self.im.executable(address): return False
        first = self.instructions(address).get(address)
        if first is None or first.mnemonic != 'jmp' or len(first.operands) != 1: return False
        operand = first.operands[0]
        if operand.type != X86_OP_MEM or first.reg_name(operand.mem.base) != 'rip': return False
        slot = first.address + first.size + operand.mem.disp
        return slot in self.im.guards and slot not in self.im.guard_checks

    def process(self, function, ins, state):
        state = dict(state)
        ops, mnemonic = ins.operands, ins.mnemonic
        following = ins.address + ins.size
        if mnemonic.startswith('ret'):
            result = state.get('rax', UNKNOWN)
            merged = join_values(self.summaries.get(function, frozenset()), result)
            if merged != self.summaries.get(function):
                self.summaries[function] = merged
                for caller, address in self.callers[function]:
                    key = (caller,address)
                    if key not in self.queued:
                        self.queue.append(key); self.queued.add(key)
            return
        if mnemonic in ('ud2','int3','hlt'): return
        if mnemonic in ('call','jmp') and ops:
            if mnemonic == 'call' and ops[0].type == X86_OP_IMM and self.cfg_dispatch_thunk(ops[0].imm):
                # The thunk is shared by many callers. Entering it would join
                # unrelated RAX targets and argument states, creating a false
                # SystemBuffer-to-slot pairing. Resolve RAX at this callsite.
                targets = state.get('rax', UNKNOWN)
            else:
                targets = self.read(ins, ops[0], state)
            self.nonimage_call(ins, targets, state, function)
            if any(k == 'guard' for k,_ in targets):
                targets = join_values(frozenset((k,x) for k,x in targets if k != 'guard'), state.get('rax',UNKNOWN))
            self.readonly_image_call(ins, targets, function)
            self.finding(ins, targets, state, function)
            for kind, address in targets:
                if kind in ('va','code_target') and address is not None and self.im.executable(address):
                    if mnemonic == 'jmp' and address in self.instructions(function):
                        self.enqueue(function,address,state)
                    else:
                        if not self.instructions(address):
                            self.limitations.add('unresolved_direct_callee')
                            if mnemonic == 'call': self.continuation(function,ins,state)
                            continue
                        entry = {k:v for k,v in state.items() if isinstance(k,str) and k != 'rsp'}
                        entry['rsp'] = value('stack')
                        for skind, sp in state.get('rsp',UNKNOWN):
                            if skind == 'stack' and sp is not None:
                                for i in range(4):
                                    old = ('stack',sp+0x20+i*8)
                                    if old in state: entry[('stack',0x28+i*8)] = state[old]
                        self.enqueue(address,address,entry)
                        self.callers[address].add((function,ins.address))
                        if mnemonic == 'call' and address in self.summaries:
                            self.continuation(function,ins,state,self.summaries[address])
                        elif mnemonic == 'jmp' and address in self.summaries:
                            # Tail-return summary propagates back through the caller.
                            merged = join_values(self.summaries.get(function,frozenset()),self.summaries[address])
                            if merged != self.summaries.get(function):
                                self.summaries[function] = merged
                                for key in self.callers[function]:
                                    if key not in self.queued: self.queue.append(key); self.queued.add(key)
                elif kind == 'guard_check':
                    # CFG checks validate target; they do not invoke it. Preserve
                    # RAX slot provenance for the actual subsequent call.
                    if mnemonic == 'call': self.enqueue(function,following,state)
                    else: self.limitations.add('guard_check_tail_transfer')
                elif kind in ('import','slot','readonly_slot'):
                    self.limitations.add('external_call_memory_effects_unmodeled')
                    if mnemonic == 'call': self.continuation(function,ins,state)
                else:
                    self.limitations.add('unresolved_indirect_call' if mnemonic == 'call' else 'unresolved_indirect_jump')
                    self.limitations.add('external_call_memory_effects_unmodeled')
                    if mnemonic == 'call': self.continuation(function,ins,state)
            return
        if mnemonic.startswith('j') or mnemonic.startswith('loop'):
            self.branch_joins += 1
            self.enqueue(function,following,state)
            if ops and ops[0].type == X86_OP_IMM: self.enqueue(function,ops[0].imm,state)
            else: self.limitations.add('unresolved_control_flow_edge')
            return
        if mnemonic in ('mov','movabs','movzx','movsx','movsxd') and len(ops) == 2:
            self.write(ins,ops[0],self.read(ins,ops[1],state),state)
        elif mnemonic == 'lea' and len(ops) == 2:
            self.write(ins,ops[0],self.address(ins,ops[1],state),state)
        elif mnemonic.startswith('cmov') and len(ops) == 2:
            self.write(ins,ops[0],join_values(self.read(ins,ops[0],state),self.read(ins,ops[1],state)),state)
        elif mnemonic in ('add','sub','inc','dec','xor','and','or','shl','sal','shr','sar','imul') and ops:
            left = self.read(ins,ops[0],state)
            right = self.read(ins,ops[-1],state) if len(ops)>1 else value('const',1)
            if mnemonic == 'xor' and len(ops)==2 and ops[0].type==ops[1].type==X86_OP_REG and ops[0].reg==ops[1].reg:
                result=value('const',0)
            else:
                results=[]
                for kind,x in left:
                    for rkind,y in right:
                        # Exact switch target sets are finite because the image
                        # table is finite. Subsequent arithmetic must re-enter
                        # the widening domain rather than grow an exact set.
                        arithmetic_kind = 'va' if kind == 'code_target' else 'const' if kind == 'relative_target' else kind
                        if x is None or y is None or rkind!='const':
                            if kind=='relative_target' and rkind=='va' and x is not None and y is not None and mnemonic=='add': results.append(value('code_target',x+y))
                            else: results.append(value(arithmetic_kind,None) if arithmetic_kind in POINTERS|{'buffer_data'} else UNKNOWN)
                        elif mnemonic in ('add','inc'): results.append(value(arithmetic_kind,x+y))
                        elif mnemonic in ('sub','dec'): results.append(value(arithmetic_kind,x-y))
                        elif kind=='const':
                            if mnemonic=='xor': z=x^y
                            elif mnemonic=='and': z=x&y
                            elif mnemonic=='or': z=x|y
                            elif mnemonic in ('shl','sal'): z=x << (y&63)
                            elif mnemonic in ('shr','sar'): z=x >> (y&63)
                            else: z=x*y
                            results.append(value('const',z & 0xffffffffffffffff))
                        else: results.append(join_values(value(kind,None),UNKNOWN))
                result=join_values(*results) if results else UNKNOWN
            self.write(ins,ops[0],result,state)
        elif mnemonic == 'push' and ops:
            state['rsp']=self.shift(state.get('rsp',UNKNOWN),-8)
            for kind,offset in state['rsp']:
                if kind=='stack' and offset is not None: state[(kind,offset)]=self.read(ins,ops[0],state)
        elif mnemonic == 'pop' and ops:
            values=[state.get((k,x),UNKNOWN) for k,x in state.get('rsp',UNKNOWN)]
            self.write(ins,ops[0],join_values(*values),state)
            state['rsp']=self.shift(state.get('rsp',UNKNOWN),8)
        elif 'movs' in mnemonic or 'stos' in mnemonic:
            self.limitations.add('rep_memory_effects_overapproximated')
            if 'movs' in mnemonic:
                sources=join_values(*(value('buffer_data',offset) if kind=='buffer' else state.get((kind,offset),UNKNOWN)
                                      for kind,offset in state.get('rsi',UNKNOWN)))
            else: sources=state.get('rax',UNKNOWN)
            for kind,offset in state.get('rdi',UNKNOWN):
                state[(kind,None)]=join_values(state.get((kind,None),UNKNOWN),sources,UNKNOWN)
            state['rsi']=self.shift(state.get('rsi',UNKNOWN),None)
            state['rdi']=self.shift(state.get('rdi',UNKNOWN),None)
            state['rcx']=UNKNOWN
        elif mnemonic not in ('cmp','test','nop','endbr64','cld','std','lfence','mfence','sfence'):
            written=False
            for op in ops:
                if op.access & CS_AC_WRITE:
                    self.write(ins,op,UNKNOWN,state); written=True
            # Implicit writes (e.g. MUL, LODS) must not leave stale provenance.
            try:
                _, regs = ins.regs_access()
                for reg in regs:
                    name=canonical(ins.reg_name(reg))
                    if name not in ('rflags','eflags'): state[name]=UNKNOWN; written=True
            except (AttributeError,ValueError): pass
            if written: self.limitations.add('unmodeled_instruction_effects')
        if function != self.root and any(op.type == X86_OP_MEM and op.access & CS_AC_WRITE for op in ops):
            self.limitations.add('helper_memory_effects_not_propagated')
        self.enqueue(function,following,state)

    @staticmethod
    def shift(val, delta):
        return frozenset((kind, offset+delta if offset is not None and delta is not None else None) for kind,offset in val)

    def run(self):
        self.enqueue(self.root,self.root,{'rcx':value('device'),'rdx':value('irp'),'rsp':value('stack')})
        while self.queue and self.steps < self.budget:
            key=self.queue.popleft(); self.queued.remove(key)
            self.steps+=1
            self.process(key[0],self.code[key[0]][key[1]],self.states[key])
        if self.queue: self.limitations.add('fixed_point_budget_exhausted')
        return not self.queue


def analyze_dispatch(image, roots, budget=100000):
    """Analyze VA dispatch roots. ``budget`` counts transfer evaluations per root.

    A completed fixed point is distinct from complete semantic coverage: material
    limitations remain explicit. No findings is not a security/safety claim.
    """
    roots=sorted(set(roots))
    findings=[]; suspects=[]; object_calls=[]; readonly_calls=[]; limitations=set(); metrics={'transfer_evaluations':0,'join_updates':0,'branch_joins':0,'instruction_states':0,'functions':0,'max_queue':0}
    completed=0
    for root in roots:
        flow=Flow(image,root,budget)
        completed+=flow.run()
        findings.extend(flow.findings.values()); suspects.extend(flow.suspects.values())
        object_calls.extend(flow.nonimage_indirect.values())
        readonly_calls.extend(flow.readonly_image_indirect.values())
        limitations.update(flow.limitations)
        metrics['transfer_evaluations']+=flow.steps
        metrics['join_updates']+=flow.joins
        metrics['branch_joins']+=flow.branch_joins
        metrics['instruction_states']+=len(flow.states)
        metrics['functions']+=len(flow.code)
        metrics['max_queue']=max(metrics['max_queue'],flow.max_queue)
    if not roots: limitations.add('device_control_dispatch_not_resolved')
    complete=bool(roots) and completed==len(roots)
    return {'analysis_model':'dispatch-rooted finite fixed-point MAY dataflow; predicates discarded',
            'coverage':{'status':'FIXED_POINT_COMPLETE' if complete else 'INCOMPLETE',
                        'complete':complete,'dispatch_roots_total':len(roots),'dispatch_roots_completed':completed,
                        'semantic_coverage_complete':complete and not limitations},
            'findings':findings,'unproven_writable_indirect_calls':suspects,
            'nonimage_indirect_call_leads':object_calls,
            'read_only_image_pointer_calls':readonly_calls,
            'limitations':sorted(limitations),'metrics':metrics,
            'predicates':'DISCARDED_AT_JOINS_NOT_RUNTIME_CONFIRMED'}
