#!/usr/bin/env python3
"""The catalogue of ready-made categories for LuCI "Lists -> Catalogue": every v2fly domain-list-community category
(with its include: lines, as lists-update fetch_v2fly takes them), the runetfreedom geosite (domains) and geoip
(addresses) lists, with how many entries each has today. Counted the way lists-update normalises them
(norm_domains / norm_cidr), so the number on the page is what the router will load.
Public data only, nothing is sent anywhere. Run before a release:
    python tools/geo-catalog.py packages/luci-app-detour/root/www/luci-static/resources/detour/geo-catalog.json
"""
import io, json, re, sys, tarfile, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

V2FLY_TGZ = 'https://codeload.github.com/v2fly/domain-list-community/tar.gz/refs/heads/master'
RFGS = 'https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geosite@release/'
RFIP = 'https://cdn.jsdelivr.net/gh/runetfreedom/russia-blocked-geoip@release/text/'
RFGS_LIST = 'https://api.github.com/repos/runetfreedom/russia-blocked-geosite/contents/?ref=release'
RFIP_LIST = 'https://api.github.com/repos/runetfreedom/russia-blocked-geoip/contents/text?ref=release'

RE_DOM = re.compile(r'^[a-z0-9_]([a-z0-9_.-]*[a-z0-9])?\.([a-z][a-z0-9-]*[a-z0-9]|[a-z]{2,})$')
RE_CIDR = re.compile(r'^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?')


def get(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'detour-geo-catalog'})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as e:
            if i == tries - 1:
                raise
            time.sleep(2)


def norm_domains(text):
    out = set()
    for line in text.lower().splitlines():
        line = line.strip()
        if not line or line[0] in '#![':
            continue
        line = re.sub(r'\s+#.*$', '', line)
        if re.match(r'^(include|keyword|regexp|ext):', line):
            continue
        m = re.match(r'^(domain|full):(.*)$', line)
        d = re.split(r'(:@|\s)', m.group(2))[0] if m else line.split()[0]
        d = re.sub(r'^\*\.', '', d).lstrip('.').rstrip('.')
        if RE_DOM.match(d) and d not in ('localhost', 'local', 'broadcasthost'):
            out.add(d)
    return out


def norm_cidr(text):
    out = set()
    for line in text.splitlines():
        m = RE_CIDR.match(line)
        if not m:
            continue
        a = [int(m.group(i)) for i in range(1, 5)]
        if max(a) > 255 or a[0] in (0, 127) or a[0] >= 224 or (m.group(6) and int(m.group(6)) > 32):
            continue
        out.add(m.group(0).strip())
    return out


def v2fly():
    data = {}
    with tarfile.open(fileobj=io.BytesIO(get(V2FLY_TGZ)), mode='r:gz') as t:
        for m in t.getmembers():
            p = m.name.split('/')
            if len(p) == 3 and p[1] == 'data' and m.isfile():
                data[p[2]] = t.extractfile(m).read().decode('utf-8', 'replace')
    out = []
    for name in sorted(data):
        seen, queue, doms = set(), [name], set()
        while queue and len(seen) < 200:
            n = queue.pop(0)
            if n in seen or n not in data:
                continue
            seen.add(n)
            for l in data[n].lower().splitlines():
                m = re.match(r'^\s*include:([a-z0-9!._-]*)', l)
                if m:
                    queue.append(m.group(1))
            doms |= norm_domains(data[n])
        # kept with 0 too (only TLDs, keywords or regexps - nothing a router can use): the router's own listing of
        # the names must not take such a category for a new one
        out.append([name, len(doms)])
    return out


def listing(url, ext):
    return sorted(x['name'][:-len(ext)] for x in json.loads(get(url)) if x['name'].endswith(ext))


def count_all(base, names, norm):
    # jsDelivr limits a burst (403): the same file from GitHub itself then
    raw = base.replace('https://cdn.jsdelivr.net/gh/', 'https://raw.githubusercontent.com/').replace('@release/', '/release/')
    def one(n):
        for b in (base, raw):
            try:
                return [n, len(norm(get(b + n + '.txt').decode('utf-8', 'replace')))]
            except Exception as e:
                err = e
        print('  skip %s: %s' % (n, err), file=sys.stderr)
        return [n, 0]
    with ThreadPoolExecutor(8) as ex:
        return [x for x in ex.map(one, names) if x[1] > 0]


def main(out):
    print('v2fly…', file=sys.stderr)
    v = v2fly()
    print('runetfreedom geosite…', file=sys.stderr)
    gs = count_all(RFGS, listing(RFGS_LIST, '.txt'), norm_domains)
    print('runetfreedom geoip…', file=sys.stderr)
    gi = count_all(RFIP, listing(RFIP_LIST, '.txt'), norm_cidr)
    cat = {'generated': time.strftime('%Y-%m-%d'), 'v2fly': v, 'rfgs': gs, 'rfip': gi}
    open(out, 'w', encoding='utf-8', newline='\n').write(json.dumps(cat, separators=(',', ':')) + '\n')
    print('%d v2fly, %d geosite, %d geoip -> %s' % (len(v), len(gs), len(gi), out), file=sys.stderr)


if __name__ == '__main__':
    main(sys.argv[1])
