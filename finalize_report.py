"""Merge refreshed WDM flow with the completed KMDF enrichment.

The earlier KMDF run was intentionally retained while a CFG-callsite and
stack-argument precision fix was validated. This combines independent results
without opening any device or executing an installed driver.
"""
from __future__ import annotations

import collections
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent / 'reports'
WDM = HERE / 'installed-v4-wdm.json'
WDF = HERE / 'installed-final.json'
OUTPUT = HERE / 'installed-verified.json'
REGISTERS = {'rcx', 'rdx', 'r8', 'r9'}


def main():
    wdm = json.loads(WDM.read_text(encoding='utf-8'))['results']
    wdf = json.loads(WDF.read_text(encoding='utf-8'))['results']
    indexed = {item['file'].lower(): item for item in wdf}
    if len(wdm) != len(wdf) or len(indexed) != len(wdf):
        raise RuntimeError('inventory mismatch')
    for report in wdm:
        enriched = indexed[report['file'].lower()]
        if report.get('sha256') != enriched.get('sha256'):
            raise RuntimeError('image hash mismatch: ' + report['file'])
        registration = enriched.get('wdf_callback_registration')
        flow = enriched.get('wdf_callback_analysis')
        if registration:
            report['wdf_callback_registration'] = registration
        if flow:
            strong, stack_only = [], []
            for finding in flow['findings']:
                names = set(finding.get('wdf_input_buffer_arguments', []))
                if names & REGISTERS:
                    strong.append(finding)
                else:
                    finding['stack_only_input_lead'] = bool(names)
                    stack_only.append(finding)
            flow['findings'] = strong
            flow['unproven_writable_indirect_calls'].extend(stack_only)
            report['wdf_callback_analysis'] = flow
            report['findings'].extend(strong)
            report['unproven_writable_indirect_calls'].extend(
                flow['unproven_writable_indirect_calls'])
        has_completed_model = bool(
            (report.get('device_control_dispatch_rvas') and
             (report.get('fixed_point_analysis') or {}).get('coverage', {}).get('complete')) or
            (registration and registration.get('roots_rvas') and flow and
             flow.get('coverage', {}).get('complete')))
        report['classification'] = ('PATTERN_CANDIDATE' if report.get('findings') else
                                    'NO_CANDIDATE_IN_MODELED_PATHS' if has_completed_model else
                                    'INCONCLUSIVE')
        report['classification_scope'] = ('Only the bounded, modeled dispatch/callback graph; '
                                          'not proof of driver-wide absence, feasible IOCTL input, '
                                          'or user accessibility. Stack-only taint is a review lead.')
        report['schema_version'] = 3
    summary = dict(collections.Counter(x['classification'] for x in wdm))
    OUTPUT.write_text(json.dumps({'results': wdm, 'summary': summary}, indent=2),
                      encoding='utf-8')
    print(summary)
    print('WDM roots', sum(bool(x.get('device_control_dispatch_rvas')) for x in wdm))
    print('WDF imports', sum(bool(x.get('wdf_callback_registration')) for x in wdm))
    print('WDF callback roots', sum(bool((x.get('wdf_callback_registration') or {}).get('roots_rvas')) for x in wdm))
    print('WDF complete', sum(bool((x.get('wdf_callback_analysis') or {}).get('coverage', {}).get('complete')) for x in wdm))
    print('Strong WDF candidate images',
          [Path(x['file']).name for x in wdm if (x.get('wdf_callback_analysis') or {}).get('findings')])


if __name__ == '__main__':
    main()
