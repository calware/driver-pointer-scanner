import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from offline_validation import validate_row
from user_interaction_scan import analyze_one

ROOT=Path(__file__).resolve().parent
MMCSS=Path(r'C:\Windows\System32\drivers\mmcss.sys')


def fixture(name):
    path=(ROOT/'fixtures'/name).resolve()
    return analyze_one({'file':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()},
                       init_budget=10000,flow_budget=10000)


class OfflineValidationTests(unittest.TestCase):
    def test_positive_and_readonly_replay_reach_expected_local_target(self):
        for name,kind in [('positive-O2.sys','WRITABLE_IMAGE_SLOT'),
                          ('readonly-O2.sys','READ_ONLY_IMAGE_POINTER')]:
            with self.subTest(name=name):
                row=fixture(name)
                result=validate_row(row,max_sites=2)
                site=next(s for s in result['sites'] if s['pointer_kind']==kind)
                hit=next(a for a in site['attempts'] if a['status']=='CALLSITE_HIT')
                self.assertTrue(hit['target_matches_image_pointer'])
                self.assertEqual(hit['actual_target_rva'],'0x1000')
                self.assertEqual(site['offline_evidence_score']['tier'],'STRONG_SYNTHETIC_EVIDENCE')
                self.assertEqual(result['no_live_reachability_claim'],True)

    def test_unrelated_buffer_is_broad_only(self):
        result=validate_row(fixture('unrelated-O2.sys'),max_sites=2)
        site=result['sites'][0]
        self.assertFalse(next(s for s in fixture('unrelated-O2.sys')['sites'])['input_buffer_variant_candidate'])
        self.assertTrue(any(a['status']=='CALLSITE_HIT' for a in site['attempts']))

    @unittest.skipUnless(MMCSS.exists(),'installed mmcss.sys absent')
    def test_installed_mmcss_three_create_callbacks_without_file_write(self):
        before=hashlib.sha256(MMCSS.read_bytes()).hexdigest()
        row=analyze_one({'file':str(MMCSS),'sha256':before},30000,30000)
        result=validate_row(row,max_sites=3)
        self.assertEqual(len(result['sites']),3)
        self.assertTrue(all(site['event']=='CreateFile' and
                            site['attempts'][0]['status']=='CALLSITE_HIT' and
                            site['attempts'][0]['target_matches_image_pointer']
                            for site in result['sites']))
        self.assertEqual(before,hashlib.sha256(MMCSS.read_bytes()).hexdigest())

    def test_scanner_stdout_is_json_when_output_omitted(self):
        completed=subprocess.run([sys.executable,'scanner.py','fixtures/positive-O2.sys','--census'],
                                 cwd=ROOT,capture_output=True,text=True,check=True)
        document=json.loads(completed.stdout)
        self.assertEqual(document['summary'],{'PATTERN_CANDIDATE':1})
        self.assertTrue(document['results'][0]['structural_callback_sites'])


if __name__=='__main__':unittest.main()
