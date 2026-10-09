import hashlib
import tempfile
import unittest
import struct
from types import SimpleNamespace
from pathlib import Path
import pefile
from scanner import Analyzer, Image, scan, UNKNOWN
from init_flow import analyze_initialization
from init_emulator import emulate_registration

ROOT=Path(__file__).resolve().parent

class ScannerTests(unittest.TestCase):
    def test_compiled_variants(self):
        for variant in ('positive','helper','readonly','unrelated','internal'):
            for optimization in ('Od','O2'):
                with self.subTest(variant=variant,optimization=optimization):
                    path=ROOT/'fixtures'/f'{variant}-{optimization}.sys'
                    before=hashlib.sha256(path.read_bytes()).hexdigest()
                    result=scan(path,census=True)
                    self.assertNotEqual(result['classification'],'ERROR',result)
                    self.assertEqual(bool(result['findings']),variant in ('positive','helper'),result)
                    self.assertEqual(before,hashlib.sha256(path.read_bytes()).hexdigest())
                    if result['findings']:
                        witness=result['findings'][0]['modeled_path_feasibility']
                        self.assertEqual(witness['status'],'SAT_PARTIAL_MODEL')
                        self.assertEqual(int(witness['witness']['ioctl_0_32'],16),0x226000)

    def test_broad_variant_catches_input_independent_callback(self):
        broad=scan(ROOT/'fixtures'/'unrelated-O2.sys',engine='legacy')
        self.assertFalse(broad['findings'])
        calls=broad['path_refined_writable_indirect_calls']
        self.assertEqual(len(calls),1,calls)
        self.assertEqual(calls[0]['modeled_path_feasibility']['status'],'SAT_PARTIAL_MODEL')
        self.assertFalse(calls[0]['input_argument_required'])
        self.assertFalse(scan(ROOT/'fixtures'/'readonly-O2.sys',engine='legacy')
                         ['path_refined_writable_indirect_calls'])
        self.assertFalse(scan(ROOT/'fixtures'/'internal-O2.sys',engine='legacy')
                         ['path_refined_writable_indirect_calls'])

    def test_rebased_image(self):
        pe=pefile.PE(str(ROOT/'fixtures'/'positive-O2.sys'))
        pe.relocate_image(0x180000000)
        pe.OPTIONAL_HEADER.ImageBase=0x180000000
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'rebased.sys'; pe.write(str(path))
            self.assertTrue(scan(path)['findings'])

    def test_unsatisfiable_integer_path(self):
        analyzer=Analyzer(Image(ROOT/'fixtures'/'positive-O2.sys'))
        predicates=(('je',('cmp',('ioctl',0),('const',0x226000),32),True),
                    ('jne',('cmp',('ioctl',0),('const',0x226000),32),True))
        self.assertEqual(analyzer.feasibility(predicates)['status'],'UNSAT')

    def test_signed_test_predicate(self):
        analyzer=Analyzer(Image(ROOT/'fixtures'/'positive-O2.sys'))
        predicates=(('jl',('test',('input_length',0),('input_length',0),32),True),)
        answer=analyzer.feasibility(predicates)
        self.assertEqual(answer['status'],'SAT_PARTIAL_MODEL')
        self.assertGreaterEqual(int(answer['witness']['input_length_0_32'],16),0x80000000)

    def test_nonreturning_helper_does_not_reach_callback(self):
        original=Image(ROOT/'fixtures'/'positive-O2.sys')
        base=original.base; slot=base+0x3000; leaf=base+0x1100; start=base+0x1000
        # A valid buffer is placed in nonvolatile RBX, then a UD2 helper terminates execution.
        body=bytes.fromhex('488b5a18')
        body+=b'\xe8'+struct.pack('<i',leaf-(start+len(body)+5))
        body+=bytes.fromhex('488bcb')
        body+=bytes.fromhex('488b05')+struct.pack('<i',slot-(start+len(body)+7))
        body+=bytes.fromhex('ffd0c3')
        code={start:{i.address:i for i in original.cs.disasm(body,start)},
              leaf:{i.address:i for i in original.cs.disasm(bytes.fromhex('0f0b'),leaf)}}
        fake=SimpleNamespace(base=base,functions={start:start+len(body),leaf:leaf+2},imports={},guards=set(),guard_checks=set(),
            instructions=lambda address:code.get(address,{}),
            executable=lambda address:address in (start,leaf,base+0x1200),
            writable=lambda address:address==slot,
            section=lambda address:SimpleNamespace(Name=b'.data',Characteristics=0x80000000) if address==slot else SimpleNamespace(Name=b'.text',Characteristics=0x20000000) if address in (start,leaf,base+0x1200) else None,
            pointer=lambda address:base+0x1200)
        analyzer=Analyzer(fake); analyzer.phase='dispatch'
        analyzer.walk(start,{'rdx':('irp',0),'rsp':('stack',0)})
        self.assertFalse(analyzer.findings)

    def test_guard_check_is_not_callback_invocation(self):
        analyzer=Analyzer(Image(ROOT/'fixtures'/'positive-O2.sys'))
        instruction=next(iter(analyzer.im.instructions(analyzer.im.entry).values()))
        analyzer.indirect(instruction,('guard_check',0),{'rax':('slot',analyzer.im.base+0x3000),'rcx':('buffer',0)},[analyzer.im.entry])
        self.assertFalse(analyzer.findings)

    def test_unresolved_branch_prevents_noreturn_inference(self):
        image=Image(ROOT/'fixtures'/'positive-O2.sys')
        start=image.entry
        code={i.address:i for i in image.cs.disasm(bytes.fromhex('74020f0b'),start)}
        image.instructions=lambda address:code if address==start else {}
        image.functions[start]=start+4
        analyzer=Analyzer(image)
        result=analyzer.walk(start,{'rsp':('stack',0)})
        self.assertNotEqual(result[0],'noreturn')
        self.assertIn('unresolved_branch',analyzer.limitations)

    def test_truncated_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'bad.sys'; path.write_bytes(b'MZ')
            self.assertEqual(scan(path)['classification'],'ERROR')

    def test_fixed_point_registration_on_chained_and_bulk_real_drivers(self):
        for filename,expected in [('rasacd.sys',0x2680),('rootmdm.sys',0x1090),('netbios.sys',0xede0)]:
            with self.subTest(driver=filename):
                path=Path('C:/Windows/System32/drivers')/filename
                self.assertIn(hex(expected),analyze_initialization(Image(path),30000)['device_control_dispatch_rvas'])

    def test_synthetic_entry_uses_copy_and_discovers_registration(self):
        fixture=ROOT/'fixtures'/'positive-O2.sys'
        before=hashlib.sha256(fixture.read_bytes()).hexdigest()
        result=emulate_registration(Image(fixture),30000)
        self.assertEqual(result['status'],'RETURNED')
        self.assertIn('0x1100',result['device_control_dispatch_rvas'])
        self.assertEqual(before,hashlib.sha256(fixture.read_bytes()).hexdigest())

if __name__=='__main__': unittest.main()
