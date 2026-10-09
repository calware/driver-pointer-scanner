import hashlib
import unittest
from pathlib import Path

from user_interaction_scan import analyze_one


class UserInteractionTests(unittest.TestCase):
    def scan_fixture(self, name):
        path = (Path(__file__).resolve().parent / 'fixtures' / name).resolve()
        return analyze_one({'file': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()},
                           init_budget=10000, flow_budget=10000)

    def test_readonly_pointer_is_separate_from_writable_input_variant(self):
        row = self.scan_fixture('readonly-O2.sys')
        self.assertIn('0x10a0', row['entry_roots']['CreateFile'])
        self.assertTrue(any(s['event'] == 'DeviceIoControl' and
                            s['pointer_kind'] == 'READ_ONLY_IMAGE_POINTER' and
                            not s['input_buffer_variant_candidate'] for s in row['sites']))

    def test_original_narrow_variant_is_preserved(self):
        row = self.scan_fixture('positive-O2.sys')
        self.assertTrue(row['entry_roots']['ReadFile'])
        self.assertTrue(row['entry_roots']['WriteFile'])
        self.assertTrue(any(s['event'] == 'DeviceIoControl' and
                            s['pointer_kind'] == 'WRITABLE_IMAGE_SLOT' and
                            s['input_buffer_variant_candidate'] for s in row['sites']))


if __name__ == '__main__':
    unittest.main()
