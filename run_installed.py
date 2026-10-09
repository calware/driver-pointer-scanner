"""Scan system images and SCM inventory paths. Does not open device handles."""
import collections
import hashlib
import json
import os
import argparse
from pathlib import Path
from scanner import scan

root=Path(__file__).resolve().parent
reports=root/'reports'; reports.mkdir(exist_ok=True)
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--reuse-census',action='store_true',help='Reuse structural surveys when the SHA256 is identical')
args=parser.parse_args()
previous={}
if args.reuse_census and (reports/'installed.json').exists():
    previous={r.get('sha256'):r for r in json.loads((reports/'installed.json').read_text())['results']}
services=json.loads((reports/'services.json').read_text(encoding='utf-8-sig'))
paths={str(p).lower():p for p in Path(os.environ['SystemRoot'],'System32','drivers').glob('*.sys')}
for service in services:
    path=service.get('PathName')
    if not path: continue
    path=os.path.expandvars(path.strip('"'))
    if path.startswith('\\??\\'): path=path[4:]
    if path.lower().startswith('\\systemroot\\'): path=os.environ['SystemRoot']+path[11:]
    if path.lower().startswith('system32\\'): path=str(Path(os.environ['SystemRoot'])/path)
    p=Path(path)
    if p.is_file() and p.suffix.lower()=='.sys': paths[str(p).lower()]=p
results=[]; integrity=[]
for n,p in enumerate(sorted(paths.values(),key=lambda p:str(p).lower()),1):
    digest=hashlib.sha256(p.read_bytes()).hexdigest()
    cached=previous.get(digest)
    function_rvas=None if cached is None else {site['function_rva'] for site in cached.get('structural_callback_sites',[])}
    r=scan(p,census=True,census_function_rvas=function_rvas,
           engine='fixedpoint',emulate_init=True,flow_budget=50000)
    results.append(r)
    after=hashlib.sha256(p.read_bytes()).hexdigest()
    integrity.append({'file':str(p),'sha256_before':r.get('sha256'),'sha256_after':after,
                      'unchanged':r.get('sha256')==after})
    print(f"[{n}/{len(paths)}] {p.name}: {r['classification']}; structural sites={len(r.get('structural_callback_sites',[]))}",flush=True)
    # Preserve progress even if a large image or external file fails later.
    (reports/'installed.json').write_text(json.dumps({'summary':dict(collections.Counter(x['classification'] for x in results)),
        'results':results},indent=2),encoding='utf-8')
(reports/'integrity.json').write_text(json.dumps(integrity,indent=2),encoding='utf-8')
print(json.dumps(dict(collections.Counter(x['classification'] for x in results))))
