"""Add KMDF callback analysis to a completed read-only installed-image scan.

This preserves the expensive WDM results and structural census, while
independently checking every image for static WDF queue registration.
"""
from __future__ import annotations

import collections
import argparse
import hashlib
import json
from pathlib import Path

from scanner import Image
from wdf_probe import discover_wdf_io_control
from wdf_flow import analyze_wdf_callbacks

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'reports' / 'installed-v4-wdm.json'
TARGET = HERE / 'reports' / 'installed-final.json'


def disposition(report):
    if report.get('findings'):
        return 'PATTERN_CANDIDATE'
    wdm = report.get('fixed_point_analysis') or {}
    wdf = report.get('wdf_callback_analysis') or {}
    if ((report.get('device_control_dispatch_rvas') and (wdm.get('coverage') or {}).get('complete'))
            or ((report.get('wdf_callback_registration') or {}).get('roots_rvas')
                and (wdf.get('coverage') or {}).get('complete'))):
        return 'NO_CANDIDATE_IN_MODELED_PATHS'
    return 'INCONCLUSIVE'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-after', type=int, default=0,
                        help='Reuse the first N completed entries in the checkpoint output')
    args = parser.parse_args()
    payload = json.loads(SOURCE.read_text(encoding='utf-8'))
    results = payload['results']
    if args.resume_after:
        previous = json.loads(TARGET.read_text(encoding='utf-8'))['results']
        if len(previous) != len(results):
            raise RuntimeError('checkpoint inventory length mismatch')
        for index in range(args.resume_after):
            if previous[index]['file'].lower() != results[index]['file'].lower() or \
                    previous[index].get('sha256') != results[index].get('sha256'):
                raise RuntimeError(f'checkpoint inventory mismatch at {index + 1}')
            results[index] = previous[index]
    integrity = []
    for index, report in enumerate(results, 1):
        path = Path(report['file'])
        try:
            image = None if index <= args.resume_after else Image(path)
            if image is not None and 'WdfVersionBind' in image.imports.values() and not report.get('wdf_callback_registration'):
                registration = discover_wdf_io_control(image)
                report['wdf_callback_registration'] = registration
                roots = {image.base + int(x, 0) for x in registration['roots_rvas']}
                if roots:
                    flow = analyze_wdf_callbacks(image, roots, 30000)
                    report['wdf_callback_analysis'] = flow
                    report.setdefault('findings', []).extend(flow['findings'])
                    report.setdefault('unproven_writable_indirect_calls', []).extend(
                        flow['unproven_writable_indirect_calls'])
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            unchanged = digest == report.get('sha256')
            integrity.append({'file': str(path), 'sha256_before': report.get('sha256'),
                              'sha256_after': digest, 'unchanged': unchanged})
            report['classification'] = disposition(report)
            report['classification_scope'] = ('Only the bounded, modeled dispatch/callback graph; '
                                              'not a proof of driver-wide absence or user accessibility.')
            report['schema_version'] = 3
        except Exception as exc:
            report['wdf_enrichment_error'] = f'{type(exc).__name__}: {exc}'
            report['classification'] = 'INCONCLUSIVE'
        print(f'[{index}/{len(results)}] {path.name}: {report["classification"]}', flush=True)
        if index % 25 == 0:
            TARGET.write_text(json.dumps({'results': results,
                'summary': dict(collections.Counter(r['classification'] for r in results))}, indent=2),
                encoding='utf-8')
    TARGET.write_text(json.dumps({'results': results,
        'summary': dict(collections.Counter(r['classification'] for r in results))}, indent=2),
        encoding='utf-8')
    (HERE / 'reports' / 'integrity-enriched.json').write_text(json.dumps(integrity, indent=2),
                                                                encoding='utf-8')
    print('Summary:', collections.Counter(r['classification'] for r in results))
    print('Unchanged:', sum(x['unchanged'] for x in integrity), '/', len(integrity))


if __name__ == '__main__':
    main()
