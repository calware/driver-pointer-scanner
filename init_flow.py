"""Finite MAY analysis of DriverEntry writes to WDM dispatch table."""
from __future__ import annotations

from collections import defaultdict, deque
from capstone.x86 import X86_OP_MEM, X86_OP_IMM
from flow_engine import Flow, value, join_state


class InitFlow(Flow):
    def __init__(self, image, budget):
        super().__init__(image,image.entry,budget)
        self.registrations=defaultdict(set)
        self.registration_sites=defaultdict(set)

    def record(self, addresses, targets, ins):
        for kind, offset in addresses:
            if kind!='driver' or offset is None or not 0x70<=offset<=0x148 or (offset-0x70)%8:
                continue
            major=(offset-0x70)//8
            for vkind, target in targets:
                if vkind in ('va','code_target') and target is not None and self.im.executable(target):
                    self.registrations[major].add(target)
                    self.registration_sites[major].add(ins.address)

    def write(self, ins, op, val, state):
        if op.type==X86_OP_MEM:
            self.record(self.address(ins,op,state),val,ins)
        super().write(ins,op,val,state)

    def process(self, function, ins, state):
        if ins.mnemonic.startswith('rep stos') and len(ins.operands)>=2 and ins.operands[0].size==8:
            state=dict(state)
            counts=[n for kind,n in state.get('rcx',()) if kind=='const' and n is not None and 0<=n<=64]
            destinations=[(kind,offset) for kind,offset in state.get('rdi',()) if kind=='driver' and offset is not None]
            if counts and destinations:
                values=state.get('rax',())
                for count in counts:
                    for kind,base in destinations:
                        for index in range(count):
                            self.record(value(kind,base+8*index),values,ins)
                # The generic transfer widens the post-state, preserving soundness.
            else:
                self.limitations.add('unresolved_bulk_dispatch_registration')
        super().process(function,ins,state)

    def run(self):
        self.enqueue(self.root,self.root,{'rcx':value('driver'),
                                          'rdx':value('registry'),
                                          'rsp':value('stack')})
        while self.queue and self.steps<self.budget:
            key=self.queue.popleft(); self.queued.remove(key)
            self.steps+=1
            self.process(key[0],self.code[key[0]][key[1]],self.states[key])
        if self.queue: self.limitations.add('fixed_point_budget_exhausted')
        return not self.queue


def analyze_initialization(image,budget=50000):
    engine=InitFlow(image,budget)
    complete=engine.run()
    return {'analysis_model':'DriverEntry fixed-point MAY registration analysis; branches joined',
            'coverage':{'status':'FIXED_POINT_COMPLETE' if complete else 'INCOMPLETE','complete':complete},
            'dispatch_rvas_by_major':{str(k):[hex(x-image.base) for x in sorted(v)]
                                      for k,v in engine.registrations.items() if v},
            'device_control_dispatch_rvas':[hex(x-image.base) for x in sorted(engine.registrations[14])],
            'create_dispatch_rvas':[hex(x-image.base) for x in sorted(engine.registrations[0])],
            'registration_sites':{str(k):[hex(x-image.base) for x in sorted(v)] for k,v in engine.registration_sites.items()},
            'limitations':sorted(engine.limitations),
            'metrics':{'transfer_evaluations':engine.steps,'instruction_states':len(engine.states),
                       'functions':len(engine.code),'join_updates':engine.joins}}


class LocalInitFlow(InitFlow):
    """Analyze one initializer function, recording calls without descending.

    This avoids spending the entire fixed-point budget in early callees before
    a later MajorFunction assignment in the caller is reached.
    """
    def __init__(self, image, root, initial, budget):
        super().__init__(image,budget)
        self.root=root
        self.initial=initial
        self.outgoing=defaultdict(list)

    def process(self,function,ins,state):
        if ins.mnemonic=='call' and ins.operands and ins.operands[0].type==X86_OP_IMM:
            target=ins.operands[0].imm
            if self.im.executable(target) and self.instructions(target):
                outgoing={key:val for key,val in state.items() if isinstance(key,str) and key!='rsp'}
                outgoing['rsp']=value('stack')
                self.outgoing[target].append((ins.address,outgoing))
            self.continuation(function,ins,state)
            return
        super().process(function,ins,state)

    def run(self):
        self.enqueue(self.root,self.root,self.initial)
        while self.queue and self.steps<self.budget:
            key=self.queue.popleft();self.queued.remove(key)
            self.steps+=1
            self.process(key[0],self.code[key[0]][key[1]],self.states[key])
        if self.queue:self.limitations.add('local_function_budget_exhausted')
        return not self.queue


def recover_registrations_local(image, max_functions=80, max_depth=4,
                                budget_per_function=5000):
    """DriverEntry call-chain MAY recovery with explicit registration sites."""
    initial={'rcx':value('driver'),'rdx':value('registry'),'rsp':value('stack')}
    queue=deque([(image.entry,initial,(image.entry,))])
    seen={}
    registrations=defaultdict(set);sites=defaultdict(set);chains=defaultdict(list)
    functions=0;limits=set()
    while queue and functions<max_functions:
        root,state,chain=queue.popleft()
        merged,changed=join_state(seen.get(root),state)
        if not changed:continue
        seen[root]=merged
        engine=LocalInitFlow(image,root,merged,budget_per_function)
        complete=engine.run();functions+=1
        if not complete:limits.add('local_function_budget_exhausted')
        for major,targets in engine.registrations.items():
            for target in targets:
                registrations[major].add(target)
                sites[major].update(engine.registration_sites[major])
                chains[(major,target)].append(chain)
        if len(chain)>=max_depth:continue
        for target,edges in engine.outgoing.items():
            if target in chain:continue
            for callsite,next_state in edges:
                if any(k=='driver' for k,_ in next_state.get('rcx',())) or any(
                    k=='driver' for k,_ in next_state.get('rdx',())) or any(
                    k=='driver' for k,_ in next_state.get('r8',())):
                    queue.append((target,next_state,chain+(target,)))
    if queue:limits.add('local_call_chain_limit')
    return {'dispatch_rvas_by_major':{str(k):[hex(x-image.base) for x in sorted(v)]
                                      for k,v in registrations.items()},
            'registration_sites':{str(k):[hex(x-image.base) for x in sorted(v)]
                                  for k,v in sites.items()},
            'call_chains':{f'{major}:{hex(target-image.base)}':
                           [[hex(x-image.base) for x in chain] for chain in paths[:4]]
                           for (major,target),paths in chains.items()},
            'functions_analyzed':functions,'limitations':sorted(limits),
            'analysis_model':'DriverEntry direct-call chain; function-local MAY flow; callees summarized as unknown'}
