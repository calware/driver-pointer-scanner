import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from offline_validation import validate_row, emulate_site, _ioctl_candidates
from scanner import Image
from user_interaction_scan import analyze_one

ROOT=Path(__file__).resolve().parent
MMCSS=Path(r'C:\Windows\System32\drivers\mmcss.sys')
AFD=Path(r'C:\Windows\System32\drivers\afd.sys')
AFD_SHA256='c6da5fb094ecbe65e9a2ab7a2efb08e67bf8e1e91542fab44683597ce24492a1'


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
                hit=next(a for a in site['attempts'] if a['status']=='TARGET_ENTERED')
                self.assertTrue(hit['target_matches_image_pointer'])
                self.assertTrue(hit['target_entered'])
                self.assertEqual(hit['actual_target_rva'],'0x1000')
                self.assertEqual(site['offline_evidence_score']['tier'],'STRONG_SYNTHETIC_EVIDENCE')
                self.assertEqual(result['no_live_reachability_claim'],True)

    def test_unrelated_buffer_is_broad_only(self):
        result=validate_row(fixture('unrelated-O2.sys'),max_sites=2)
        site=result['sites'][0]
        self.assertFalse(next(s for s in fixture('unrelated-O2.sys')['sites'])['input_buffer_variant_candidate'])
        self.assertTrue(any(a['status']=='TARGET_ENTERED' for a in site['attempts']))

    @unittest.skipUnless(MMCSS.exists(),'installed mmcss.sys absent')
    def test_installed_mmcss_three_create_callbacks_without_file_write(self):
        before=hashlib.sha256(MMCSS.read_bytes()).hexdigest()
        row=analyze_one({'file':str(MMCSS),'sha256':before},30000,30000)
        result=validate_row(row,max_sites=3)
        self.assertEqual(len(result['sites']),3)
        self.assertTrue(all(site['event']=='CreateFile' and
                            site['attempts'][0]['status']=='TARGET_ENTERED' and
                            site['attempts'][0]['target_matches_image_pointer']
                            for site in result['sites']))
        self.assertEqual(before,hashlib.sha256(MMCSS.read_bytes()).hexdigest())

    def test_scanner_stdout_brief_and_explicit_json(self):
        brief=subprocess.run([sys.executable,'scanner.py','fixtures/positive-O2.sys','--census'],
                             cwd=ROOT,capture_output=True,text=True,check=True)
        self.assertIn('positive-O2.sys: PATTERN_CANDIDATE',brief.stdout)
        completed=subprocess.run([sys.executable,'scanner.py','fixtures/positive-O2.sys','--census','--format','json'],
                                 cwd=ROOT,capture_output=True,text=True,check=True)
        document=json.loads(completed.stdout)
        self.assertEqual(document['summary'],{'PATTERN_CANDIDATE':1})
        self.assertTrue(document['results'][0]['structural_callback_sites'])

    def test_offline_flow_budget_is_not_silently_capped(self):
        for budget,complete in ((1,False),(10000,True)):
            with self.subTest(budget=budget):
                completed=subprocess.run([sys.executable,'scanner.py','fixtures/positive-O2.sys',
                                          '--offline-validate','--offline-flow-budget',str(budget),
                                          '--format','json'],cwd=ROOT,capture_output=True,text=True,check=True)
                row=json.loads(completed.stdout)['results'][0]['user_interaction_analysis']
                self.assertEqual(row['entry_coverage']['DeviceIoControl']['complete'],complete)

    @unittest.skipUnless(AFD.exists() and hashlib.sha256(AFD.read_bytes()).hexdigest()==AFD_SHA256,
                         'specific installed afd.sys build absent')
    def test_installed_afd_indexed_ioctl_table_witness_read_only(self):
        before=hashlib.sha256(AFD.read_bytes()).hexdigest()
        image=Image(AFD)
        site={'entry_model':'WDM','event':'DeviceIoControl','pointer_kind':'IMAGE_POINTER_TABLE',
              'dispatch_rva':'0x14cc0','function_rva':'0x14cc0','call_rva':'0x14d8e',
              'slot_rva':'0x78430','initial_target_rva':'0x39160'}
        codes=_ioctl_candidates(image,image.base+0x14cc0,site)
        self.assertEqual(codes[0],0x12003)
        attempt=emulate_site(image,site,{'name':'afd_index_0','file_name':'','ioctl':codes[0],
                                         'input_length':4,'output_length':64})
        self.assertEqual(attempt['status'],'TARGET_ENTERED',attempt)
        self.assertEqual(attempt['actual_target_rva'],'0x39160')
        self.assertTrue(attempt['target_matches_image_pointer'])
        self.assertEqual(before,hashlib.sha256(AFD.read_bytes()).hexdigest())


if __name__=='__main__':unittest.main()
