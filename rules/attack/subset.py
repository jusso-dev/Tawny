"""Build techniques.json from an ATT&CK Enterprise STIX bundle.

Usage: python3 -I rules/attack/subset.py <enterprise-attack-X.Y.json> <repo root> > rules/attack/techniques.json
Keeps only techniques named by rules (attack.tNNNN tags) or coverage.yaml.
Update attack_version below and in coverage.yaml when the release changes.
"""
import json,re,sys,hashlib,glob,os
src=sys.argv[1]
raw=open(src,'rb').read()
d=json.loads(raw)
repo=sys.argv[2]
used=set()
for f in glob.glob(repo+'/rules/**/*.y*ml',recursive=True):
    for m in re.findall(r'attack\.(t\d{4}(?:\.\d{3})?)', open(f,encoding='utf-8',errors='ignore').read(), re.I):
        used.add(m.upper())
for m in re.findall(r'\bid:\s*(T\d{4}(?:\.\d{3})?)', open(os.path.join(repo,'rules/attack/coverage.yaml')).read()):
    used.add(m)
tech={}
tactic_names={}
for o in d['objects']:
    if o.get('type')=='x-mitre-tactic' and not o.get('revoked') and not o.get('x_mitre_deprecated'):
        tactic_names[o['x_mitre_shortname']]=(o['name'], next(r['external_id'] for r in o['external_references'] if r.get('source_name')=='mitre-attack'))
    if o.get('type')!='attack-pattern' or o.get('revoked') or o.get('x_mitre_deprecated'): continue
    ext=next((r['external_id'] for r in o.get('external_references',[]) if r.get('source_name')=='mitre-attack'),None)
    if not ext: continue
    tech[ext]={'id':ext,'name':o['name'],'tactics':[p['phase_name'] for p in o.get('kill_chain_phases',[]) if p.get('kill_chain_name')=='mitre-attack'],'platforms':o.get('x_mitre_platforms',[])}
missing=sorted(u for u in used if u not in tech)
out=[]
for u in sorted(used):
    if u in tech:
        t=dict(tech[u])
        if '.' in u and u.split('.')[0] in tech:
            t['name']=tech[u.split('.')[0]]['name']+': '+t['name']
        out.append(t)
byid={o['id']:o for o in d['objects']}
matrix=next(o for o in d['objects'] if o.get('type')=='x-mitre-matrix' and o.get('name')=='Enterprise ATT&CK')
order=[byid[t]['x_mitre_shortname'] for t in matrix['tactic_refs']]
tactics=[{'shortname':s,'name':tactic_names[s][0],'id':tactic_names[s][1]} for s in order if s in tactic_names]
extra_tactics=[s for s in tactic_names if s not in order]
doc={'attack_spec':'enterprise-attack','attack_version':'20.1','source':'https://github.com/mitre-attack/attack-stix-data/blob/master/enterprise-attack/enterprise-attack-20.1.json','source_sha256':hashlib.sha256(raw).hexdigest(),'note':'Subset: only techniques named by Tawny rules or rules/attack/coverage.yaml. Regenerate with rules/attack/subset.py.','tactics':tactics,'techniques':out}
print(json.dumps(doc,indent=1,sort_keys=False))
sys.stderr.write(f"used={len(used)} vendored={len(out)} missing={missing} extra_tactics={extra_tactics}\n")
