import sys, json, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

src = sys.argv[1]
dst = sys.argv[2]
CONCURRENCY = 20

def get_exit(data):
    pr = data.get('probe_results', {})
    for k in ('ipv4', 'ipv6'):
        v = pr.get(k, {})
        if v.get('ok') and isinstance(v.get('exit'), dict):
            return v['exit']
    return {}

def check_one(line):
    line = line.strip()
    if not line:
        return None
    if ':' in line:
        ip, port = line.split(':', 1)
        port = port.split('#')[0]
    else:
        ip, port = line, '443'
    url = f'https://api.090227.xyz/check?proxyip={ip}:{port}'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.0'})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())
        if data.get('success'):
            e = get_exit(data)
            parts = [str(e.get('country', '')), str(e.get('city', '')), 'AS' + str(e.get('asn', '')), str(e.get('asOrganization', ''))]
            return f'{ip}:{port}#{" ".join(parts)}'
        else:
            return f'{ip}:{port}#timeout'
    except Exception:
        return f'{ip}:{port}#timeout'

with open(src) as f:
    lines = [line.strip() for line in f if line.strip()]

total = len(lines)
done = 0
results = []

with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
    fut_map = {ex.submit(check_one, line): line for line in lines}
    for fut in as_completed(fut_map):
        r = fut.result()
        if r:
            results.append(r)
        done += 1
        print(f'[{done}/{total}] {r}', flush=True)

results.sort()
with open(dst, 'w') as out:
    for r in results:
        out.write(r + '\n')