import unittest
from pathlib import Path

from broad_scan import make_row
from scanner import scan

ROOT = Path(__file__).resolve().parent


class BroadScanTests(unittest.TestCase):
    def test_input_independent_callback_is_broad_only(self):
        report = scan(ROOT/'fixtures'/'unrelated-O2.sys', engine='fixedpoint', emulate_init=True)
        row = make_row(report, budget=10000, depth=6)
        self.assertFalse(report['findings'])
        self.assertEqual(row['broad_classification'], 'BROAD_SAT_PARTIAL_LEAD')
        self.assertEqual(len(row['writable_image_slot_calls']), 1)
        site = row['writable_image_slot_calls'][0]
        self.assertFalse(site['narrow_input_variant_candidate'])
        self.assertEqual(site['static_path_evidence']['modeled_path_feasibility']['status'],
                         'SAT_PARTIAL_MODEL')

    def test_readonly_and_internal_are_not_broad_slot_leads(self):
        for name in ('readonly-O2.sys', 'internal-O2.sys'):
            with self.subTest(name=name):
                report = scan(ROOT/'fixtures'/name, engine='fixedpoint', emulate_init=True)
                row = make_row(report, budget=10000, depth=6)
                self.assertFalse(row['writable_image_slot_calls'])


if __name__ == '__main__': unittest.main()
