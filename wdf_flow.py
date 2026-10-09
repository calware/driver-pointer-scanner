"""Bounded, read-only MAY flow from x64 KMDF EvtIoDeviceControl roots.

WDF table indices are from WDK 1.x wdffuncenum.h. A WDF input buffer is
deliberately distinct from IRP.AssociatedIrp.SystemBuffer: WDF abstracts the
request transfer method. No candidate proves a reachable or successful call.
"""
from __future__ import annotations

from capstone.x86 import X86_OP_IMM, X86_OP_MEM

from flow_engine import Flow, UNKNOWN, join_values, value
from scanner import Image, canonical


RETRIEVE_INPUT_BUFFER_INDEX = 269
WDM_GET_IRP_INDEX = 285
WDF_APIS = {RETRIEVE_INPUT_BUFFER_INDEX: 'WdfRequestRetrieveInputBuffer',
            WDM_GET_IRP_INDEX: 'WdfRequestWdmGetIrp'}
_POINTERS = {'wdf_request', 'wdf_table', 'wdf_input_buffer'}


class WdfFlow(Flow):
    def __init__(self, image, root, budget, event='EvtIoDeviceControl'):
        super().__init__(image, root, budget)
        self.event = event
        self.api_calls = {}
        self.table_globals = set()

    def address(self, ins, op, state):
        """Extend Flow's address algebra with WDF request/table provenance."""
        result = super().address(ins, op, state)
        mem = op.mem
        if not mem.base or ins.reg_name(mem.base) == 'rip':
            return result
        bases = state.get(canonical(ins.reg_name(mem.base)), UNKNOWN)
        if not any(kind in _POINTERS for kind, _ in bases):
            return result
        indexes = state.get(canonical(ins.reg_name(mem.index)), UNKNOWN) if mem.index else value('const')
        additions = []
        for kind, base in bases:
            if kind not in _POINTERS:
                continue
            for index_kind, index in indexes:
                offset = base + mem.disp + index * mem.scale if (base is not None and
                          index_kind == 'const' and index is not None) else None
                additions.append(value(kind, offset))
        return join_values(result, *additions)

    def read(self, ins, op, state):
        result = super().read(ins, op, state)
        if op.type != X86_OP_MEM or op.size != 8:
            return result
        addresses = self.address(ins, op, state)
        additions = []
        for kind, address in addresses:
            if kind == 'va' and address is not None and self.im.writable(address):
                # A writable pointer global is a table candidate. It is only
                # promoted to WDF evidence at a known index and Request arg.
                additions.append(value('wdf_table', 0))
                self.table_globals.add(address)
            elif kind == 'wdf_table' and address is not None and address % 8 == 0 and 0 <= address // 8 <= 500:
                additions.append(value('wdf_api', address // 8))
            elif kind == 'wdf_input_buffer':
                additions.append(value('wdf_input_data', address))
        return join_values(result, *additions) if additions else result

    def write(self, ins, op, val, state):
        # The base engine's pointer-truncation rule predates the WDF kinds.
        if op.size < 8 and any(k in _POINTERS for k, _ in val):
            val = join_values(UNKNOWN, frozenset((k, x) for k, x in val if k not in _POINTERS))
            self.limitations.add('pointer_truncation')
        super().write(ins, op, val, state)

    def _request_arg(self, state):
        # WDF table functions have a hidden WDF_DRIVER_GLOBALS* first argument.
        return any(kind == 'wdf_request' for kind, _ in state.get('rdx', UNKNOWN))

    def _is_cfg_dispatch_thunk(self, address):
        """Recognize the MSVC call thunk: jmp qword ptr [GuardCFDispatch]."""
        if not self.im.executable(address):
            return False
        code = self.instructions(address)
        first = code.get(address)
        if first is None or first.mnemonic != 'jmp' or len(first.operands) != 1:
            return False
        operand = first.operands[0]
        if operand.type != X86_OP_MEM or first.reg_name(operand.mem.base) != 'rip':
            return False
        slot = first.address + first.size + operand.mem.disp
        return slot in self.im.guards and slot not in self.im.guard_checks

    def _wdf_call(self, function, ins, state, indices):
        for index in indices:
            name = WDF_APIS.get(index)
            key = (ins.address, index)
            self.api_calls[key] = {'call_rva': hex(ins.address - self.im.base),
                                   'function_rva': hex(function - self.im.base),
                                   'api': name, 'table_index': index,
                                   'request_argument_provenance': 'wdf_request' if self._request_arg(state) else None}
            next_state = dict(state)
            if index == RETRIEVE_INPUT_BUFFER_INDEX and self._request_arg(state):
                out = state.get('r9', UNKNOWN)
                wrote = False
                for kind, offset in out:
                    if kind in ('stack', 'va') and offset is not None:
                        # MAY write: a failing NTSTATUS can leave the output
                        # untouched, and no status predicate is checked here.
                        key_out = (kind, offset)
                        next_state[key_out] = join_values(next_state.get(key_out, UNKNOWN),
                                                          value('wdf_input_buffer'))
                        wrote = True
                if not wrote:
                    self.limitations.add('wdf_input_out_parameter_unresolved')
                self.limitations.add('wdf_retrieve_success_not_proven')
                self.continuation(function, ins, next_state, value('wdf_status'))
            elif index == WDM_GET_IRP_INDEX and self._request_arg(state):
                self.continuation(function, ins, next_state, value('irp'))
            else:
                self.limitations.add('other_wdf_api_effects_unmodeled')
                self.continuation(function, ins, next_state)

    def process(self, function, ins, state):
        if ins.mnemonic == 'call' and ins.operands:
            targets = self.read(ins, ins.operands[0], state)
            if any(kind == 'guard' for kind, _ in targets):
                targets = join_values(frozenset((k, x) for k, x in targets if k != 'guard'),
                                      state.get('rax', UNKNOWN))
            if ins.operands[0].type == X86_OP_IMM and self._is_cfg_dispatch_thunk(ins.operands[0].imm):
                # Treat the thunk as a call through RAX at this callsite. Entering
                # the shared thunk joins unrelated callers and fabricates a
                # buffer/slot pairing that never coexisted in one caller.
                targets = state.get('rax', UNKNOWN)
                self.readonly_image_call(ins, targets, function)
                self.finding(ins, targets, state, function)
                indices = {index for kind, index in targets if kind == 'wdf_api' and index is not None}
                if indices:
                    self._wdf_call(function, ins, state, indices)
                if any(kind != 'wdf_api' for kind, _ in targets):
                    self.limitations.add('external_call_memory_effects_unmodeled')
                    self.continuation(function, ins, state)
                return
            indices = {index for kind, index in targets if kind == 'wdf_api' and index is not None}
            if indices:
                self._wdf_call(function, ins, state, indices)
                # Other possible targets remain unresolved MAY alternatives.
                if any(kind not in ('wdf_api', 'guard') for kind, _ in targets):
                    self.limitations.add('wdf_call_target_has_other_alternatives')
                return
        super().process(function, ins, state)

    def finding(self, ins, targets, state, function):
        # Reuse Flow's slot/argument report and augment its provenance label.
        super().finding(ins, targets, state, function)
        for kind, slot in targets:
            if kind != 'slot' or slot is None:
                continue
            key = (ins.address, slot)
            record = self.findings.get(key) or self.suspects.get(key)
            if record is None:
                continue
            wdf_args = [name for name, atoms in record['arguments'].items()
                        if any(atom['kind'] in ('wdf_input_buffer', 'wdf_input_data') for atom in atoms)]
            record['wdf_input_buffer_arguments'] = wdf_args
            record['provenance'] = sorted((['irp_system_buffer'] if record['systembuffer_arguments'] else []) +
                                          (['wdf_input_buffer'] if wdf_args else []))
            record['interpretation'] = ('Fixed-point MAY candidate; WDF retrieval success, branch predicates, '
                                        'runtime invocation and transfer method are not proved.')
            if any(name in ('rcx', 'rdx', 'r8', 'r9') for name in wdf_args):
                self.findings[key] = record
                self.suspects.pop(key, None)
            elif wdf_args:
                record['stack_only_input_lead'] = True
                self.findings.pop(key, None)
                self.suspects[key] = record

    def run(self):
        initial = {'rcx': value('wdf_queue'), 'rdx': value('wdf_request'),
                   'rsp': value('stack')}
        if self.event == 'EvtIoDeviceControl':
            initial.update({'r8': value('wdf_output_length'), 'r9': value('wdf_input_length'),
                            ('stack', 0x28): value('ioctl')})
        elif self.event in ('EvtIoRead', 'EvtIoWrite'):
            initial['r8'] = value('wdf_length')
        self.enqueue(self.root, self.root, initial)
        while self.queue and self.steps < self.budget:
            key = self.queue.popleft()
            self.queued.remove(key)
            self.steps += 1
            self.process(key[0], self.code[key[0]][key[1]], self.states[key])
        if self.queue:
            self.limitations.add('fixed_point_budget_exhausted')
        return not self.queue


def analyze_wdf_callbacks(image, rootsVAs, budget=100000, event='EvtIoDeviceControl'):
    """Analyze candidate EvtIoDeviceControl VAs, read-only, budget per root."""
    if not isinstance(image, Image) and not hasattr(image, 'instructions'):
        image = Image(image)
    roots = sorted(set(rootsVAs))
    findings, suspects, calls, object_calls, readonly_calls, limitations = [], [], [], [], [], set()
    metrics = {'transfer_evaluations': 0, 'join_updates': 0, 'branch_joins': 0,
               'instruction_states': 0, 'functions': 0, 'max_queue': 0,
               'wdf_table_candidate_globals': 0}
    completed = 0
    table_globals = set()
    for root in roots:
        flow = WdfFlow(image, root, budget, event=event)
        completed += flow.run()
        findings.extend(flow.findings.values())
        suspects.extend(flow.suspects.values())
        calls.extend(flow.api_calls.values())
        object_calls.extend(flow.nonimage_indirect.values())
        readonly_calls.extend(flow.readonly_image_indirect.values())
        limitations.update(flow.limitations)
        table_globals.update(flow.table_globals)
        for field, amount in (('transfer_evaluations', flow.steps), ('join_updates', flow.joins),
                              ('branch_joins', flow.branch_joins), ('instruction_states', len(flow.states)),
                              ('functions', len(flow.code))):
            metrics[field] += amount
        metrics['max_queue'] = max(metrics['max_queue'], flow.max_queue)
    metrics['wdf_table_candidate_globals'] = len(table_globals)
    if not roots:
        limitations.add('wdf_callback_roots_not_resolved')
    if not any(x['api'] for x in calls) and roots:
        limitations.add('supported_wdf_request_api_calls_not_resolved')
    limitations.update(('wdf_table_identity_inferred_from_writable_global_and_index',
                        'static_may_flow_only; runtime reachability and successful completion not proven',
                        'WDF input buffer is framework abstraction; transfer method and SystemBuffer identity not inferred'))
    complete = bool(roots) and completed == len(roots)
    return {'analysis_model': 'KMDF callback-rooted finite fixed-point MAY dataflow; predicates discarded',
            'coverage': {'status': 'FIXED_POINT_COMPLETE' if complete else 'INCOMPLETE',
                         'complete': complete, 'callback_roots_total': len(roots),
                         'callback_roots_completed': completed,
                         'semantic_coverage_complete': complete and not limitations},
            'findings': findings, 'unproven_writable_indirect_calls': suspects,
            'nonimage_indirect_call_leads': object_calls,
            'read_only_image_pointer_calls': readonly_calls,
            'wdf_api_calls': calls, 'limitations': sorted(limitations), 'metrics': metrics,
            'predicates': 'DISCARDED_AT_JOINS_NOT_RUNTIME_CONFIRMED'}
