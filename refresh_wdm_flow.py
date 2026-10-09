"""Recompute rooted WDM MAY flow after callsite CFG precision improvements.

Reuses the previously established 522-image inventory, root discovery, and
structural census. Only PE files are read; original SHA256 values are checked.
"""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path

from scanner import Image
from flow_engine import analyze_dispatch

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'reports' / 'installed-v3.json'
TARGET = HERE / 'reports' / 'installed-v4-wdm.json'


def main():
    reports = json.loads(SOURCE.read_text(encoding='utf-8'))['results']
    rooted = [r for r in reports if r.get('device_control_dispatch_rvas')]
    for index, report in enumerate(rooted, 1):
        image = Image(report['file'])
        if hashlib.sha256(image.raw).hexdigest() != report['sha256']:
            raise RuntimeError(f'image changed since inventory: {report["file"]}')
        roots = {image.base + int(x, 0) for x in report['device_control_dispatch_rvas']}
        flow = analyze_dispatch(image, roots, 50000)
        report['fixed_point_analysis'] = flow
        report['findings'] = flow['findings']
        report['unproven_writable_indirect_calls'] = flow['unproven_writable_indirect_calls']
        report['classification'] = ('PATTERN_CANDIDATE' if flow['findings'] else
                                    'NO_CANDIDATE_IN_MODELED_PATHS' if flow['coverage']['complete'] else
                                    'INCONCLUSIVE')
        report['classification_scope'] = ('Only the bounded, modeled dispatch graph; '
                                          'not a proof of driver-wide absence or user accessibility.')
        report['schema_version'] = 3
        print(f'[{index}/{len(rooted)}] {Path(report["file"]).name}: '
              f'{report["classification"]}; findings={len(flow["findings"])}', flush=True)
    for report in reports:
        if not report.get('device_control_dispatch_rvas'):
            report['classification'] = 'INCONCLUSIVE'
            report['classification_scope'] = ('No resolved WDM device-control dispatch; '
                                              'user accessibility and pattern unresolved.')
            report['schema_version'] = 3
    TARGET.write_text(json.dumps({'results': reports,
        'summary': dict(collections.Counter(r['classification'] for r in reports))}, indent=2),
        encoding='utf-8')
    print('Summary:', collections.Counter(r['classification'] for r in reports))


if __name__ == '__main__':
    main()
