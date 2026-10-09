"""Merge offline partitions, attach service snapshots, and verify file hashes."""
from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent / 'reports'
PARTS = [HERE/'user-interaction-installed.json'] + [HERE/f'user-interaction-part{i}.json' for i in (2,3,4)]


def main():
    baseline = json.loads((HERE/'installed-verified.json').read_text(encoding='utf-8'))['results']
    rows = [r for part in PARTS for r in json.loads(part.read_text(encoding='utf-8'))['results']]
    if len(rows) != len(baseline) or any(r['file'].lower() != b['file'].lower() for r,b in zip(rows,baseline)):
        raise RuntimeError('partition order/count does not match baseline inventory')
    services = json.loads((HERE/'services.json').read_text(encoding='utf-8-sig'))
    by_name = collections.defaultdict(list)
    for service in services:
        by_name[os.path.basename(service.get('PathName') or '').lower()].append(service)
    integrity = []
    for row, base in zip(rows, baseline):
        kind = {s['pointer_kind'] for s in row.get('sites', [])}
        row['classification'] = ('ROOTED_IMAGE_POINTER_CALL_LEAD' if kind - {'OBJECT_FIELD_INDIRECT'} else
                                 'ROOTED_OBJECT_FIELD_CALL_LEAD' if kind else
                                 row['classification'] if row['classification'] != 'ROOTED_INDIRECT_CALL_LEAD' else
                                 'INCONCLUSIVE')
        matched = by_name[os.path.basename(row['file']).lower()]
        row['service_inventory'] = [{'name':s.get('Name'), 'state':s.get('State'),
                                     'start_mode':s.get('StartMode')} for s in matched]
        after = hashlib.sha256(Path(row['file']).read_bytes()).hexdigest()
        equal = after == base.get('sha256') == row.get('sha256')
        integrity.append({'file': row['file'], 'unchanged': equal,
                          'baseline_sha256': base.get('sha256'), 'post_scan_sha256': after})
    summary = {'images': len(rows),
               'classifications': dict(collections.Counter(r['classification'] for r in rows)),
               'pointer_kinds': dict(collections.Counter(s['pointer_kind'] for r in rows for s in r.get('sites', []))),
               'events': dict(collections.Counter(s['event'] for r in rows for s in r.get('sites', []))),
               'unchanged_images': sum(x['unchanged'] for x in integrity)}
    if summary['unchanged_images'] != len(rows):
        raise RuntimeError('installed image SHA256 mismatch; refusing finalized report')
    (HERE/'user-interaction-integrity.json').write_text(json.dumps({'results':integrity,'summary':summary},indent=2),encoding='utf-8')
    (HERE/'user-interaction-reviewed.json').write_text(json.dumps({'schema_version':1,'summary':summary,
                                                                   'results':rows},indent=2),encoding='utf-8')
    print(summary)


if __name__ == '__main__':
    main()
