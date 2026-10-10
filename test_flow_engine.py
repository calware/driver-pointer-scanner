import hashlib
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from scanner import Image, Analyzer
from flow_engine import analyze_dispatch, join_values, join_state, value, UNKNOWN
from init_flow import recover_registrations_local

ROOT = Path(__file__).resolve().parent


class FlowTests(unittest.TestCase):
    def fake(self, bodies, imports=None, guards=None, checks=None):
        original = Image(ROOT/'fixtures'/'positive-O2.sys')
        base = original.base
        starts = {base+offset:code for offset,code in bodies.items()}
        code = {start:{ins.address:ins for ins in original.cs.disasm(body,start)} for start,body in starts.items()}
        slot = base+0x3000
        def executable(address):
            return address == base+0x1200 or any(start <= address < start+len(body) for start,body in starts.items())
        return SimpleNamespace(base=base,functions={s:s+len(b) for s,b in starts.items()},
             imports=imports or {},guards=guards or set(),guard_checks=checks or set(),
             instructions=lambda address:dict(code.get(address,{})),executable=executable,
             writable=lambda address:address == slot,
             section=lambda address:SimpleNamespace(Name=b'.data') if address==slot else SimpleNamespace(Name=b'.text') if executable(address) else None,
             pointer=lambda address:base+0x1200)

    @staticmethod
    def slot_call(prefix=b'', register=b'\xff\xd0', slot_rva=0x3000):
        # mov rax,[rip+slot]; call rax; ret at root RVA 0x1000.
        return prefix+b'\x48\x8b\x05'+struct.pack('<i',slot_rva-(0x1000+len(prefix)+7))+register+b'\xc3'

    def test_kind_preserving_widening_and_missing_predecessor(self):
        v=join_values(*(value('buffer',i) for i in range(20)),value('slot',123))
        self.assertIn(('buffer',None),v)
        self.assertIn(('slot',123),v)
        self.assertEqual(join_values(v,value('buffer',999)),v)
        merged,_=join_state({'rcx':value('buffer')},{'rax':value('const',1)})
        self.assertIn(('buffer',0),merged['rcx'])
        self.assertIn(('unknown',None),merged['rcx'])

    def test_local_registration_survives_early_helper_call(self):
        # DriverEntry calls an unrelated helper before registering an IOCTL root.
        root=bytes.fromhex('488bd9')
        root+=b'\xe8'+struct.pack('<i',0x1100-(0x1000+len(root)+5))
        root+=bytes.fromhex('488bcb')
        root+=b'\xe8'+struct.pack('<i',0x1200-(0x1000+len(root)+5))+b'\xc3'
        helper=b'\xc3'
        writer=b'\x48\x8d\x05'+struct.pack('<i',0x1300-0x1207)
        writer+=bytes.fromhex('488981e0000000c3')
        image=self.fake({0x1000:root,0x1100:helper,0x1200:writer,0x1300:b'\xc3'})
        image.entry=image.base+0x1000
        recovered=recover_registrations_local(image)
        self.assertEqual(recovered['dispatch_rvas_by_major']['14'],['0x1300'])
        self.assertEqual(recovered['call_chains']['14:0x1300'][0],['0x1000','0x1200'])

    @unittest.skipUnless(Path(r'C:\Windows\System32\drivers\afd.sys').exists(),'afd.sys absent')
    def test_installed_afd_local_registration_read_only(self):
        path=Path(r'C:\Windows\System32\drivers\afd.sys')
        before=hashlib.sha256(path.read_bytes()).digest()
        recovered=recover_registrations_local(Image(path))
        self.assertTrue(recovered['dispatch_rvas_by_major'].get('14'))
        self.assertEqual(before,hashlib.sha256(path.read_bytes()).digest())

    def test_loop_converges_without_losing_positive(self):
        # buffer in RCX; growing EBX loop; unknown branch eventually reaches slot.
        body=self.slot_call(bytes.fromhex('488b4a1831dbffc375fc'))
        image=self.fake({0x1000:body})
        result=analyze_dispatch(image,[image.base+0x1000],budget=1000)
        self.assertTrue(result['coverage']['complete'],result)
        self.assertTrue(result['findings'],result)
        self.assertGreater(result['metrics']['join_updates'],0)
        self.assertLess(result['metrics']['transfer_evaluations'],200)
        json.dumps(result)

    def test_join_keeps_buffer_alternative(self):
        # mov rcx,[rdx+18]; test eax,eax; jz +2; xor ecx,ecx.
        image=self.fake({0x1000:self.slot_call(bytes.fromhex('488b4a1885c0740231c9'))})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertTrue(result['findings'],result)
        self.assertTrue(result['coverage']['complete'])

    def test_budget_is_explicit_incomplete(self):
        image=self.fake({0x1000:self.slot_call(bytes.fromhex('488b4a18'))})
        result=analyze_dispatch(image,[image.base+0x1000],budget=1)
        self.assertFalse(result['coverage']['complete'])
        self.assertIn('fixed_point_budget_exhausted',result['limitations'])

    def test_spilled_buffer_restored(self):
        image=self.fake({0x1000:self.slot_call(bytes.fromhex('488b4a1848894c24284831c9488b4c2428'))})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertTrue(result['findings'],result)

    def test_guard_check_preserves_slot_but_is_not_invocation(self):
        # slot in RAX, check target through R11, then call RAX.
        prefix=bytes.fromhex('488b4a18488b05')+struct.pack('<i',0x3000-(0x1000+11))
        prefix+=bytes.fromhex('4c8b1d')+struct.pack('<i',0x3100-(0x1000+len(prefix)+7))
        image=self.fake({0x1000:prefix+bytes.fromhex('41ffd3ffd0c3')})
        image.guard_checks={image.base+0x3100}
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertEqual(len(result['findings']),1,result)

    def test_direct_cfg_dispatch_thunk_is_resolved_at_caller(self):
        # MSVC shared thunk: jmp [GuardCFDispatch]. The callback target must
        # be taken from this caller's RAX before interprocedural state joins.
        root = bytes.fromhex('488b4a18')
        root += b'\x48\x8b\x05' + struct.pack('<i', 0x3000-(0x1000+len(root)+7))
        call_at = 0x1000+len(root)
        root += b'\xe8' + struct.pack('<i', 0x1100-(call_at+5)) + b'\xc3'
        thunk = b'\xff\x25' + struct.pack('<i', 0x3100-(0x1100+6))
        image = self.fake({0x1000:root, 0x1100:thunk})
        image.guards = {image.base+0x3100}
        result = analyze_dispatch(image,[image.base+0x1000])
        self.assertEqual(len(result['findings']), 1, result)
        self.assertEqual(result['findings'][0]['call_rva'], hex(call_at))
        self.assertEqual(result['findings'][0]['function_rva'], '0x1000')

    def test_import_not_callback(self):
        image=self.fake({0x1000:self.slot_call(bytes.fromhex('488b4a18'))})
        image.imports={image.base+0x3000:'IoCompleteRequest'}
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertFalse(result['findings'],result)

    def test_object_field_indirect_call_is_separate_unverified_lead(self):
        image=self.fake({0x1000:bytes.fromhex('ff5120c3')})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertFalse(result['findings'])
        self.assertFalse(result['unproven_writable_indirect_calls'])
        lead=result['nonimage_indirect_call_leads'][0]
        self.assertEqual(lead['field_displacement'],0x20)
        self.assertEqual(lead['base_provenance'][0]['kind'],'device')
        self.assertEqual(lead['classification'],'NONIMAGE_INDIRECT_CALL_MUTABILITY_UNVERIFIED')

    def test_loaded_object_field_then_register_call(self):
        # mov rax,[rcx+20]; call rax; ret
        image=self.fake({0x1000:bytes.fromhex('488b4120ffd0c3')})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertEqual(len(result['nonimage_indirect_call_leads']),1,result)
        lead=result['nonimage_indirect_call_leads'][0]
        self.assertEqual(lead['field_chain'],[0x20])
        self.assertEqual(lead['call_rva'],'0x1004')

    def test_two_hop_object_field_then_register_call(self):
        # mov rax,[rcx+40]; mov rax,[rax+20]; call rax; ret
        image=self.fake({0x1000:bytes.fromhex('488b4140488b4020ffd0c3')})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertEqual(len(result['nonimage_indirect_call_leads']),1,result)
        self.assertEqual(result['nonimage_indirect_call_leads'][0]['field_chain'],[0x40,0x20])

    def test_read_only_image_pointer_call_is_reported_separately(self):
        image=self.fake({0x1000:self.slot_call(slot_rva=0x3100)})
        image.section=lambda address: (SimpleNamespace(Name=b'.rdata') if address==image.base+0x3100
                                       else SimpleNamespace(Name=b'.text') if image.executable(address) else None)
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertFalse(result['unproven_writable_indirect_calls'])
        self.assertEqual(result['read_only_image_pointer_calls'][0]['slot_rva'],'0x3100')
        self.assertEqual(result['read_only_image_pointer_calls'][0]['storage'],'READ_ONLY_IMAGE_SECTION')

    def test_helper_return_and_noreturn(self):
        # call helper; mov rcx,rax; slot call. Helper returns IRP.SystemBuffer.
        prefix=b'\xe8'+struct.pack('<i',0x1100-0x1005)+bytes.fromhex('488bc8')
        for helper,positive in ((bytes.fromhex('488b4218c3'),True),(bytes.fromhex('0f0b'),False)):
            image=self.fake({0x1000:self.slot_call(prefix),0x1100:helper})
            result=analyze_dispatch(image,[image.base+0x1000])
            self.assertEqual(bool(result['findings']),positive,result)
            self.assertTrue(result['coverage']['complete'])

    def test_many_relative_switch_targets_survive_join(self):
        # LEA image base, sign-extended indexed RVA table, ADD base, JMP target.
        dispatch=bytes.fromhex('488b4a18')
        dispatch+=bytes.fromhex('4c8d15')+struct.pack('<i',-(0x1000+len(dispatch)+7))
        dispatch+=bytes.fromhex('49638482004000004c01d0ffe0')
        bodies={0x1000:dispatch}
        for i in range(16):
            start=0x1100+i*0x10
            bodies[start]=bytes.fromhex('488b05')+struct.pack('<i',0x3000-(start+7))+bytes.fromhex('ffd0c3')
        image=self.fake(bodies)
        table=b''.join(struct.pack('<i',0x1100+i*0x10) for i in range(16))
        image.pe=SimpleNamespace(get_data=lambda rva,size:table[rva-0x4000:rva-0x4000+size] if rva>=0x4000 else b'')
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertTrue(result['coverage']['complete'],result)
        self.assertEqual(len(result['findings']),16,result)
        self.assertIn('switch_table_bounds_unproved',result['limitations'])

    def test_unknown_alias_write_remains_material(self):
        image=self.fake({0x1000:bytes.fromhex('488908c3')})
        result=analyze_dispatch(image,[image.base+0x1000])
        self.assertTrue(result['coverage']['complete'])
        self.assertFalse(result['coverage']['semantic_coverage_complete'])
        self.assertIn('unresolved_memory_write',result['limitations'])

    def test_fixture_positives_and_controls_read_only(self):
        for variant in ('positive','helper','readonly','unrelated','internal'):
            for opt in ('Od','O2'):
                with self.subTest(variant=variant,opt=opt):
                    path=ROOT/'fixtures'/f'{variant}-{opt}.sys'
                    before=hashlib.sha256(path.read_bytes()).hexdigest()
                    image=Image(path)
                    initialization=Analyzer(image)
                    initialization.walk(image.entry,{'rcx':('driver',0),'rdx':('registry',0),'rsp':('stack',0)})
                    roots=initialization.dispatch.get(0xe,set())
                    result=analyze_dispatch(image,roots)
                    self.assertEqual(bool(result['findings']),variant in ('positive','helper'),result)
                    self.assertEqual(result['coverage']['complete'],bool(roots),result)
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)


if __name__ == '__main__':
    unittest.main()
