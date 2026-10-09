"""Broaden offline triage to any writable image-slot call on an IOCTL path.

Consumes the completed rooted WDM/KMDF report. The narrow SystemBuffer-input
variant remains separate. A SAT partial model is a stronger static lead, not a
live execution witness or proof that user mode can open the device.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

from scanner import Analyzer, Image

HERE = Path(__file__).resolve().parent
DEFAULT_SOURCE = HERE / 'reports' / 'installed-verified.json'
DEFAULT_OUTPUT = HERE / 'reports' / 'broad-installed.json'


def _records(report, model):
    flow = report.get('fixed_point_analysis') if model == 'WDM' else report.get('wdf_callback_analysis')
    if not flow:
        return []
    records = {}
    for item in flow.get('unproven_writable_indirect_calls', []) + flow.get('findings', []):
        key = (item['dispatch_rva'], item['call_rva'], item['slot_rva'])
        strong = item in flow.get('findings', [])
        current = records.get(key)
        if current is None or strong:
            records[key] = {'variant': 'WRITABLE_IMAGE_SLOT_CALL', 'entry_model': model,
                            'dispatch_rva': key[0], 'call_rva': key[1], 'slot_rva': key[2],
                            'function_rva': item.get('function_rva'),
                            'section': item.get('section'),
                            'initial_target_rva': item.get('initial_target_rva'),
                            'instruction': item.get('instruction'),
                            'narrow_input_variant_candidate': bool(strong),
                            'narrow_input_arguments': (item.get('systembuffer_arguments', []) if model == 'WDM'
                                                       else item.get('wdf_input_buffer_arguments', [])),
                            'static_evidence_tier': 'ROOTED_FIXED_POINT_MAY',
                            'static_path_evidence': None,
                            'user_handle_access': 'UNVERIFIED',
                            'runtime_reachability': 'UNVERIFIED'}
    return list(records.values())


def refine_wdm(report, sites, budget, depth):
    roots = report.get('device_control_dispatch_rvas', [])
    if not roots or not sites:
        return {'status': 'NOT_APPLICABLE', 'limitations': []}
    image = Image(report['file'])
    if hashlib.sha256(image.raw).hexdigest() != report['sha256']:
        raise RuntimeError('installed image changed since baseline: ' + report['file'])
    analyzer = Analyzer(image, budget=budget, depth=depth)
    analyzer.phase = 'dispatch'
    for root_rva in roots:
        analyzer.steps = 0
        analyzer.walk(image.base + int(root_rva, 0),
                      {'rcx': ('device', 0), 'rdx': ('irp', 0), 'rsp': ('stack', 0)})
    evidence = collections.defaultdict(list)
    for item in analyzer.reachable_slots.values():
        key = (item['dispatch_rva'], item['call_rva'], item['slot_rva'])
        evidence[key].append(item)
    matched = 0
    for site in sites:
        key = (site['dispatch_rva'], site['call_rva'], site['slot_rva'])
        paths = evidence.get(key, [])
        if paths:
            # Prefer the path with the most represented branch predicates.
            best = max(paths, key=lambda x:x['modeled_path_feasibility'].get('modeled_predicates', 0))
            site['static_evidence_tier'] = 'SAT_PARTIAL_MODELED_PATH'
            site['static_path_evidence'] = {
                'call_chain_rvas': best['call_chain_rvas'],
                'modeled_path_feasibility': best['modeled_path_feasibility']}
            matched += 1
    return {'status': 'REFINED', 'sites_matched': matched, 'sites_total': len(sites),
            'path_search_steps': analyzer.steps,
            'limitations': sorted(analyzer.limitations)}


def make_row(report, budget, depth):
    wdm = _records(report, 'WDM')
    wdf = _records(report, 'KMDF')
    error = None
    try:
        refinement = refine_wdm(report, wdm, budget, depth)
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
        refinement = {'status': 'ERROR', 'limitations': [error]}
    sites = wdm + wdf
    complete = bool((report.get('fixed_point_analysis') or {}).get('coverage', {}).get('complete') or
                    (report.get('wdf_callback_analysis') or {}).get('coverage', {}).get('complete'))
    if any(s['static_evidence_tier'] == 'SAT_PARTIAL_MODELED_PATH' for s in sites):
        category = 'BROAD_SAT_PARTIAL_LEAD'
    elif sites:
        category = 'BROAD_ROOTED_MAY_LEAD'
    elif complete:
        category = 'NO_BROAD_IMAGE_SLOT_IN_MODELED_PATHS'
    else:
        category = 'INCONCLUSIVE'
    return {'file': report['file'], 'sha256': report.get('sha256'),
            'broad_classification': category,
            'narrow_classification': report.get('classification'),
            'writable_image_slot_calls': sites,
            'wdm_path_refinement': refinement,
            'known_limits': ['Static branch model is partial and MAY joins discard path correlation.',
                             'WDF queue registration and callback invocation are not runtime-proven.',
                             'Writable image slot is not evidence of a user-controlled pointer write.',
                             'User handle access and live IOCTL execution were not tested.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    p.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    p.add_argument('--budget', type=int, default=20000,
                   help='Legacy path-state budget per WDM root')
    p.add_argument('--depth', type=int, default=8)
    p.add_argument('--resume-after', type=int, default=0)
    a = p.parse_args()
    originals = json.loads(a.source.read_text(encoding='utf-8'))['results']
    rows = [None] * len(originals)
    if a.resume_after:
        previous = json.loads(a.output.read_text(encoding='utf-8'))['results']
        if len(previous) != len(originals): raise RuntimeError('checkpoint length mismatch')
        rows[:a.resume_after] = previous[:a.resume_after]
    for index, report in enumerate(originals, 1):
        if index <= a.resume_after:
            continue
        rows[index-1] = make_row(report, a.budget, a.depth)
        print(f'[{index}/{len(originals)}] {Path(report["file"]).name}: '
              f'{rows[index-1]["broad_classification"]}; '
              f'sites={len(rows[index-1]["writable_image_slot_calls"])}', flush=True)
        if index % 10 == 0:
            a.output.write_text(json.dumps({'results': rows, 'progress': index}, indent=2),
                                encoding='utf-8')
    categories = dict(collections.Counter(x['broad_classification'] for x in rows))
    a.output.write_text(json.dumps({'results': rows, 'summary': categories}, indent=2),
                        encoding='utf-8')
    print(categories)


if __name__ == '__main__': main()
