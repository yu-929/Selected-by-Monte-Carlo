import sys, json, urllib.request

src = sys.argv[1]
dst = sys.argv[2]

def get_exit(data):
    pr = data.get('probe_results', {})
    for k in ('ipv4', 'ipv6'):
        v = pr.get(k, {})
        if v.get('ok') and isinstance(v.get('exit'), dict):
            return v['exit']
    return {}

with open(src) as f:
    for line in f:
        ip = line.strip()
        if not ip:
            continue
        url = 'https://api.090227.xyz/check?proxyip=' + ip + ':443'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.0'})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            if data.get('success'):
                e = get_exit(data)
                parts = [str(e.get('country', '')), str(e.get('city', '')), 'AS' + str(e.get('asn', '')), str(e.get('asOrganization', ''))]
                result = ip + ':443#' + ' '.join(parts)
            else:
                result = ip + ':443#timeout'
        except Exception:
            result = ip + ':443#timeout'
        print(result)
        with open(dst, 'a') as out:
            out.write(result + '\n')