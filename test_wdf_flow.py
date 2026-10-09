"""Offline KMDF WDFREQUEST flow tests; no driver is loaded or device opened."""
import hashlib
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from scanner import Image
from wdf_flow import analyze_wdf_callbacks
from wdf_probe import discover_wdf_io_control


ROOT = Path(__file__).resolve().parent
DRIVERS = Path(r'C:\Windows\System32\drivers')


def fake_image(body, guard=False, thunk=False):
    original = Image(ROOT / 'fixtures' / 'positive-O2.sys')
    base = original.base
    code = {ins.address: ins for ins in original.cs.disasm(body, base + 0x1000)}
    thunk_code = {ins.address: ins for ins in original.cs.disasm(
        b'\xff\x25' + struct.pack('<i', 0x3100 - (0x1100 + 6)), base + 0x1100)} if thunk else {}
    section = lambda name: SimpleNamespace(Name=name)
    return SimpleNamespace(
        base=base, functions={base + 0x1000: base + 0x1000 + len(body)},
        imports={}, guards={base + 0x3100} if guard else set(), guard_checks=set(),
        instructions=lambda address: dict(code) if address == base + 0x1000 else
                                  dict(thunk_code) if address == base + 0x1100 else {},
        executable=lambda address: (base + 0x1000 <= address < base + 0x1000 + len(body)) or
                                   (thunk and base + 0x1100 <= address < base + 0x1106),
        writable=lambda address: address in (base + 0x3000, base + 0x3200),
        section=lambda address: section(b'.data' if address in (base + 0x3000, base + 0x3200)
                                        else b'.text'),
        pointer=lambda address: 0)


def rip_load(prefix, target_rva):
    # mov rax,[rip+target] at RVA 0x1000+len(prefix)
    return prefix + b'\x48\x8b\x05' + struct.pack('<i', target_rva - (0x1000 + len(prefix) + 7))


def slot_call(prefix):
    return rip_load(prefix, 0x3200) + b'\xff\xd0\xc3'


class WdfFlowTests(unittest.TestCase):
    def analyze(self, body, **kwargs):
        image = fake_image(body, **kwargs)
        result = analyze_wdf_callbacks(image, [image.base + 0x1000])
        json.dumps(result)
        self.assertTrue(result['coverage']['complete'], result)
        return result

    def test_retrieve_input_buffer_out_parameter_reaches_slot(self):
        # WdfFunctions[269](Globals,Request,0,&out,NULL), then callback(out).
        body = rip_load(b'', 0x3000) + bytes.fromhex('488b8068080000')
        body += bytes.fromhex('4c8d4c2410ffd0488b4c2410')
        result = self.analyze(slot_call(body))
        self.assertEqual([x['api'] for x in result['wdf_api_calls']],
                         ['WdfRequestRetrieveInputBuffer'])
        finding = result['findings'][0]
        self.assertEqual(finding['wdf_input_buffer_arguments'], ['rcx'])
        self.assertEqual(finding['systembuffer_arguments'], [])
        self.assertEqual(finding['provenance'], ['wdf_input_buffer'])
        self.assertIn('wdf_retrieve_success_not_proven', result['limitations'])

    def test_wdm_get_irp_systembuffer_reaches_slot(self):
        # WdfFunctions[285](Globals,Request)->IRP; [IRP+18] is SystemBuffer.
        body = rip_load(b'', 0x3000) + bytes.fromhex('488b80e8080000ffd0488b4818')
        result = self.analyze(slot_call(body))
        self.assertEqual([x['api'] for x in result['wdf_api_calls']], ['WdfRequestWdmGetIrp'])
        finding = result['findings'][0]
        self.assertEqual(finding['systembuffer_arguments'], ['rcx'])
        self.assertEqual(finding['wdf_input_buffer_arguments'], [])
        self.assertEqual(finding['provenance'], ['irp_system_buffer'])

    def test_cfg_dispatch_and_budget(self):
        body = rip_load(b'', 0x3000) + bytes.fromhex('488b8068080000')
        body += bytes.fromhex('4c8d4c2410')
        # call [rip+guard] dispatches the WDF target held in RAX.
        displacement = 0x3100 - (0x1000 + len(body) + 6)
        body += b'\xff\x15' + struct.pack('<i', displacement)
        body += bytes.fromhex('488b4c2410')
        result = self.analyze(slot_call(body), guard=True)
        self.assertEqual(result['findings'][0]['wdf_input_buffer_arguments'], ['rcx'])
        image = fake_image(body)
        short = analyze_wdf_callbacks(image, [image.base + 0x1000], budget=1)
        self.assertFalse(short['coverage']['complete'])
        self.assertIn('fixed_point_budget_exhausted', short['limitations'])

    def test_direct_cfg_dispatch_thunk(self):
        body = rip_load(b'', 0x3000) + bytes.fromhex('488b8068080000')
        body += bytes.fromhex('4c8d4c2410')
        body += b'\xe8' + struct.pack('<i', 0x1100 - (0x1000 + len(body) + 5))
        body += bytes.fromhex('488b4c2410')
        result = self.analyze(slot_call(body), guard=True, thunk=True)
        self.assertEqual(result['findings'][0]['wdf_input_buffer_arguments'], ['rcx'])

    def test_unrelated_table_without_request_provenance_is_not_wdf(self):
        body = rip_load(b'', 0x3000) + bytes.fromhex('488b806808000031d2ffd0c3')
        result = self.analyze(body)
        self.assertIsNone(result['wdf_api_calls'][0]['request_argument_provenance'])
        self.assertFalse(result['findings'])

    @unittest.skipUnless((DRIVERS / '1394ohci.sys').exists() and
                         (DRIVERS / 'USBXHCI.SYS').exists(), 'installed WDF drivers absent')
    def test_two_installed_kmdf_roots_are_analyzed_read_only(self):
        for name in ('1394ohci.sys', 'USBXHCI.SYS'):
            with self.subTest(driver=name):
                path = DRIVERS / name
                before = hashlib.sha256(path.read_bytes()).digest()
                image = Image(path)
                discovered = discover_wdf_io_control(image)
                roots = [image.base + int(rva, 16) for rva in discovered['roots_rvas']]
                self.assertTrue(roots, name)
                result = analyze_wdf_callbacks(image, roots, budget=20000)
                # Generic WDF continuations can explore a large helper graph.
                self.assertEqual(result['coverage']['complete'],
                                 'fixed_point_budget_exhausted' not in result['limitations'])
                self.assertEqual(result['coverage']['callback_roots_total'], len(roots))
                self.assertGreater(result['metrics']['transfer_evaluations'], 0)
                if name == '1394ohci.sys':
                    self.assertTrue(any(call['table_index'] == 269 and
                                        call['request_argument_provenance'] == 'wdf_request'
                                        for call in result['wdf_api_calls']), result)
                json.dumps(result)
                self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())


if __name__ == '__main__':
    unittest.main()
