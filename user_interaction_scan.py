"""Offline triage of indirect calls rooted in WDM/KMDF user-request entry paths.

The report is a bounded static MAY analysis. It never opens a device, sends a
request, loads a driver, or writes an installed image. A finding is an
engineering review lead, not proof that a user can reach the call at runtime.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from scanner import Analyzer, Image
from flow_engine import analyze_dispatch
from init_flow import analyze_initialization
from wdf_probe import discover_wdf_io_control, USER_REQUEST_EVENTS
from wdf_flow import analyze_wdf_callbacks

HERE = Path(__file__).resolve().parent
MAJORS = {0: 'CreateFile', 3: 'ReadFile', 4: 'WriteFile', 14: 'DeviceIoControl'}


def _sites(flow, event, model):
    records = {}
    for kind, name in (('WRITABLE_IMAGE_SLOT', 'unproven_writable_indirect_calls'),
                       ('WRITABLE_IMAGE_SLOT', 'findings'),
                       ('READ_ONLY_IMAGE_POINTER', 'read_only_image_pointer_calls'),
                       ('OBJECT_FIELD_INDIRECT', 'nonimage_indirect_call_leads')):
        for item in flow.get(name, []):
            actual_kind = 'IMAGE_POINTER_TABLE' if item.get('storage') == 'IMAGE_POINTER_TABLE' else kind
            key = (actual_kind, item['dispatch_rva'], item['call_rva'], item.get('slot_rva'), event)
            records[key] = {'event': event, 'entry_model': model,
                            'pointer_kind': actual_kind, 'dispatch_rva': item['dispatch_rva'],
                            'function_rva': item.get('function_rva'),
                            'call_rva': item['call_rva'], 'slot_rva': item.get('slot_rva'),
                            'section': item.get('section'),
                            'initial_target_rva': item.get('initial_target_rva'),
                            'instruction': item.get('instruction'),
                            'input_buffer_variant_candidate': name == 'findings' and event in ('DeviceIoControl', 'EvtIoDeviceControl'),
                            'field_displacement': item.get('field_displacement'),
                            'base_provenance': item.get('base_provenance'),
                            'evidence': 'ROOTED_FIXED_POINT_MAY',
                            'runtime_reachability': 'UNVERIFIED',
                            'user_handle_access': 'UNVERIFIED'}
    return list(records.values())


def analyze_one(prior, init_budget=30000, flow_budget=30000):
    path = Path(prior['file'])
    image = Image(path)
    digest = hashlib.sha256(image.raw).hexdigest()
    if digest != prior.get('sha256'):
        raise RuntimeError('image SHA256 differs from prior read-only baseline')
    row = {'file': str(path), 'sha256': digest, 'entry_roots': {},
           'sites': [], 'entry_coverage': {}, 'limitations': [],
           'runtime_reachability': 'UNVERIFIED', 'user_handle_access': 'UNVERIFIED'}
    roots = collections.defaultdict(set)
    # The existing report contains abstract DriverEntry roots and, when needed,
    # its fixed-point fallback. Recompute registrations for Read and Write.
    abstract = Analyzer(image, budget=12000, depth=5)
    abstract.walk(image.entry, {'rcx': ('driver', 0), 'rdx': ('registry', 0),
                                'rsp': ('stack', 0)})
    for major in MAJORS:
        roots[major].update(abstract.dispatch.get(major, ()))
    row['limitations'].extend('abstract_init:' + x for x in abstract.limitations)
    row['abstract_init_steps'] = abstract.steps
    prior_init = prior.get('fixed_point_initialization') or {}
    # Legacy stored only two of the four majors. Analyze DriverEntry again
    # when it has a plausible WDM device-creation path.
    if len(image.raw) <= 64 * 1024 * 1024 and set(image.imports.values()) & {
            'IoCreateDevice', 'IoCreateDeviceSecure', 'WdmlibIoCreateDeviceSecure'}:
        init = analyze_initialization(image, init_budget)
        for major, rvas in init['dispatch_rvas_by_major'].items():
            if int(major) in MAJORS:
                roots[int(major)].update(image.base + int(x, 0) for x in rvas)
        row['wdm_initialization_coverage'] = init['coverage']
        row['limitations'].extend('fixed_init:' + x for x in init['limitations'])
    else:
        row['wdm_initialization_coverage'] = {'status': 'NOT_RUN_NO_WDM_DEVICE_CREATION_IMPORT_OR_SIZE_LIMIT'}
    for major, event in MAJORS.items():
        roots[major].update(image.base + int(x, 0) for x in prior.get(
            'device_control_dispatch_rvas' if major == 14 else 'create_dispatch_rvas' if major == 0 else '_none_', []))
        group = sorted(roots[major])
        row['entry_roots'][event] = [hex(x-image.base) for x in group]
        if group:
            flow = analyze_dispatch(image, group, flow_budget)
            row['sites'].extend(_sites(flow, event, 'WDM'))
            row['entry_coverage'][event] = flow['coverage']
            row['limitations'].extend(event + ':' + x for x in flow['limitations'])
        else:
            row['entry_coverage'][event] = {'status': 'ROOT_NOT_RESOLVED', 'complete': False}
    if 'WdfVersionBind' in image.imports.values():
        registration = discover_wdf_io_control(image)
        for event in USER_REQUEST_EVENTS:
            group = [image.base + int(x, 0) for x in registration['roots_by_event'][event]]
            row['entry_roots'][event] = registration['roots_by_event'][event]
            if group:
                flow = analyze_wdf_callbacks(image, group, flow_budget, event=event)
                row['sites'].extend(_sites(flow, event, 'KMDF'))
                row['entry_coverage'][event] = flow['coverage']
                row['limitations'].extend(event + ':' + x for x in flow['limitations'])
            else:
                row['entry_coverage'][event] = {'status': 'ROOT_NOT_RESOLVED', 'complete': False}
        row['wdf_registration_count'] = len(registration['registrations'])
    row['sites'] = list({(s['event'], s['entry_model'], s['pointer_kind'], s['dispatch_rva'],
                          s['call_rva'], s['slot_rva']): s for s in row['sites']}.values())
    row['limitations'] = sorted(set(row['limitations']))
    image_sites = any(s['pointer_kind'] != 'OBJECT_FIELD_INDIRECT' for s in row['sites'])
    row['classification'] = ('ROOTED_IMAGE_POINTER_CALL_LEAD' if image_sites else
                             'ROOTED_OBJECT_FIELD_CALL_LEAD' if row['sites'] else
                             'NO_INDIRECT_CALL_IN_MODELED_PATHS' if any(
                                 c.get('complete') for c in row['entry_coverage'].values()) else 'INCONCLUSIVE')
    row['scope'] = ('A resolved entry and a fixed-point MAY path do not prove a user-visible device, '
                    'request success, path feasibility, or execution on this machine. Object-field '
                    'leads do not establish that the field belongs to this image.')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=HERE/'reports'/'installed-verified.json')
    p.add_argument('--output', type=Path, help='Write JSON/checkpoints here; omit to print JSON to stdout')
    p.add_argument('--init-budget', type=int, default=30000)
    p.add_argument('--flow-budget', type=int, default=30000)
    p.add_argument('--resume', action='store_true')
    p.add_argument('--start', type=int, default=1, help='1-based first inventory row for a partition')
    p.add_argument('--stop', type=int, default=0, help='1-based last inventory row; zero means final row')
    args = p.parse_args()
    if args.resume and not args.output:
        p.error('--resume requires --output')
    all_prior = json.loads(args.source.read_text(encoding='utf-8'))['results']
    if args.start < 1 or (args.stop and args.stop < args.start):
        p.error('invalid inventory partition')
    prior = all_prior[args.start-1:args.stop or None]
    rows = []
    if args.resume and args.output.exists():
        rows = json.loads(args.output.read_text(encoding='utf-8'))['results']
    for index in range(len(rows), len(prior)):
        try:
            row = analyze_one(prior[index], args.init_budget, args.flow_budget)
        except Exception as exc:
            row = {'file': prior[index]['file'], 'sha256': prior[index].get('sha256'),
                   'classification': 'ERROR', 'error': f'{type(exc).__name__}: {exc}'}
        rows.append(row)
        if args.output:
            print(f'[{args.start+index}/{len(all_prior)}] {Path(row["file"]).name}: '
                  f'{row["classification"]} {len(row.get("sites", []))}', flush=True)
        if args.output and (index+1) % 10 == 0:
            args.output.write_text(json.dumps({'results': rows, 'progress': index+1}, indent=2), encoding='utf-8')
    summary = {'classifications': dict(collections.Counter(x['classification'] for x in rows)),
               'pointer_kinds': dict(collections.Counter(s['pointer_kind'] for r in rows for s in r.get('sites', []))),
               'events': dict(collections.Counter(s['event'] for r in rows for s in r.get('sites', [])))}
    document={'results':rows,'summary':summary}
    if args.output:
        args.output.write_text(json.dumps(document, indent=2), encoding='utf-8')
        print(summary)
    else:
        print(json.dumps(document,indent=2))


if __name__ == '__main__':
    main()
