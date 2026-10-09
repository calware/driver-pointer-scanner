"""Attach service state and evidence groups to the broad read-only report."""
from __future__ import annotations

import collections
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent / 'reports'
SOURCE = HERE / 'broad-installed-final.json'
TARGET = HERE / 'broad-installed-reviewed.json'


def group(row):
    sites = row['writable_image_slot_calls']
    sat = [s for s in sites if s['static_evidence_tier'] == 'SAT_PARTIAL_MODELED_PATH']
    if any(s.get('direct_writer_sites') or s['slot_initialization_evidence'] == 'INITIAL_EXECUTABLE_TARGET'
           for s in sat):
        return 'PATH_SAT_WITH_INITIALIZATION_EVIDENCE'
    if sat: return 'PATH_SAT_INITIALIZATION_UNRESOLVED'
    if sites: return 'ROOTED_MAY_SLOT_CALL'
    if row['broad_classification'] == 'NO_BROAD_IMAGE_SLOT_IN_MODELED_PATHS':
        return 'NO_IMAGE_SLOT_IN_MODELED_PATHS'
    return 'INCONCLUSIVE'


def main():
    rows = json.loads(SOURCE.read_text(encoding='utf-8'))['results']
    services = json.loads((HERE/'services.json').read_text(encoding='utf-8-sig'))
    byname = collections.defaultdict(list)
    for service in services:
        byname[os.path.basename(service.get('PathName') or '').lower()].append(service)
    for row in rows:
        matched = byname[os.path.basename(row['file']).lower()]
        row['service_inventory'] = [{'name':s.get('Name'), 'state':s.get('State'),
                                     'start_mode':s.get('StartMode')} for s in matched]
        row['service_state_scope'] = ('Read-only SCM inventory snapshot; file presence and registration '
                                      'do not prove a live device is openable.')
        row['broad_evidence_group'] = group(row)
        row['broad_pattern_scope'] = ('Writable image-slot call rooted in a modeled WDM device-control '
                                      'or KMDF EvtIoDeviceControl path. No request-input argument is required. '
                                      'Static evidence only; runtime execution and user handle access unverified.')
    summary = dict(collections.Counter(row['broad_evidence_group'] for row in rows))
    sat_running = sum(row['broad_evidence_group'].startswith('PATH_SAT') and
                      any(s['state']=='Running' for s in row['service_inventory']) for row in rows)
    sat_trace = sum(row['broad_evidence_group'].startswith('PATH_SAT') and
                    any(s['static_evidence_tier']=='SAT_PARTIAL_MODELED_PATH' and
                        any(w.get('source_hint',{}).get('symbol')=='WmiTraceMessage'
                            for w in s.get('direct_writer_sites',[]))
                        for s in row['writable_image_slot_calls']) for row in rows)
    TARGET.write_text(json.dumps({'schema_version': 1, 'summary': summary,
        'sat_partial_images_with_running_service': sat_running,
        'sat_partial_images_with_WmiTraceMessage_slot': sat_trace,
        'results': rows}, indent=2),encoding='utf-8')
    print(summary)
    print('SAT partial images with Running service:',sat_running)
    print('SAT partial images with WmiTraceMessage slot:',sat_trace)


if __name__ == '__main__': main()
