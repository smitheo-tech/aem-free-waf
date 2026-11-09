"""Detection rate vs SecLists payloads (sent as ?q=<payload>). Downloads lists to .cache/seclists."""
import sys,yaml
from urllib.parse import quote
from pathlib import Path; R=Path(__file__).resolve().parent.parent; sys.path.insert(0,str(R/'tests')); import run_tests as t
cdn=yaml.safe_load(open(R/'config'/'cdn.yaml'))
rules=[r for r in cdn['data']['trafficFilters']['rules'] if 'rateLimit' not in r]
import urllib.request
S='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/'
SRC={'Generic-SQLi.txt':'Databases/SQLi/Generic-SQLi.txt','XSS-Jhaddix.txt':'XSS/human-friendly/XSS-Jhaddix.txt','LFI-Jhaddix.txt':'LFI/LFI-Jhaddix.txt','command-injection-commix.txt':'command-injection-commix.txt'}
def fetch(f):
    c=R/'.cache'/'seclists'/f; c.parent.mkdir(parents=True,exist_ok=True)
    if not c.exists(): c.write_bytes(urllib.request.urlopen(S+SRC[f],timeout=60).read())
    return open(c,errors='ignore')
for f in ['Generic-SQLi.txt','XSS-Jhaddix.txt','LFI-Jhaddix.txt','command-injection-commix.txt']:
    pl=[l.rstrip('\n') for l in fetch(f) if l.strip()]
    hit=blk=0; miss=[]
    for p in pl:
        pr=t.props({'url':'/content/site/en/search.html?q='+quote(p,safe='%' if __import__('re').search('%[0-9a-fA-F]{2}',p) else '')}); h={'user-agent':'Mozilla/5.0'}
        m=[t.action_type(r) for r in rules if t.ev(r['when'],pr,h)]
        hit+=bool(m); blk+=('block' in m)
        if not m: miss.append(p)
    print(f"{f:30} {len(pl):5}  detected {hit/len(pl):6.1%}  blocked-now {blk/len(pl):6.1%}   e.g. missed: {miss[:3]}")
