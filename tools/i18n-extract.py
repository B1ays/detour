#!/usr/bin/env python3
"""Extract translatable strings of luci-app-detour, as LuCI's build/i18n-scan.pl does: _('…'), N_(n, '…', '…') in the
views and shared modules (string literals joined with + are one message) and "title" in the menu JSON.
usage: i18n-extract.py <luci-app-detour dir>
  -> prints JSON [{"id":…, "plural":…|null, "where":…, "refs": ["<path in the package>:<line>", …]}]"""
import json, os, re, sys

def js_string(src, i):
    q = src[i]; i += 1; out = []
    while src[i] != q:
        c = src[i]
        if c == '\\':
            n = src[i + 1]
            out.append({'n': '\n', 't': '\t', "'": "'", '"': '"', '\\': '\\'}.get(n, '\\' + n)); i += 2; continue
        out.append(c); i += 1
    return ''.join(out), i + 1

def skip_ws(src, i):
    while i < len(src) and src[i] in ' \t\r\n': i += 1
    return i

def concat(src, i):
    """string literals joined by + starting at i; returns (text, index after) or (None, i)"""
    i = skip_ws(src, i)
    if src[i] not in '\'"': return None, i
    parts = []
    while True:
        s, i = js_string(src, i); parts.append(s)
        j = skip_ws(src, i)
        if j < len(src) and src[j] == '+':
            k = skip_ws(src, j + 1)
            if src[k] in '\'"': i = k; continue
        return ''.join(parts), i

def extract(root):
    out, seen = [], {}
    views = os.path.join(root, 'root/www/luci-static/resources/view/detour')
    shared = os.path.join(root, 'root/www/luci-static/resources/detour')
    files = [ os.path.join(views, f) for f in sorted(os.listdir(views)) ] +         [ os.path.join(shared, f) for f in sorted(os.listdir(shared)) if f.endswith('.js') ]
    for path in files:
        f = os.path.basename(path)
        rel = os.path.relpath(path, root).replace(os.sep, '/')
        src = open(path, encoding='utf-8').read()
        for m in re.finditer(r'(?<![\w.])(N_|_)\(', src):
            ref = '%s:%d' % (rel, src.count('\n', 0, m.start()) + 1)
            i = m.end()
            if m.group(1) == '_':
                s, _ = concat(src, i)
                if s is None: continue
                key = (s, None)
            else:
                # N_(count, 'singular', 'plural')
                depth, j = 0, i
                while True:
                    c = src[j]
                    if c in '([{': depth += 1
                    elif c in ')]}': depth -= 1
                    elif c == ',' and depth == 0: break
                    j += 1
                s1, j = concat(src, j + 1)
                j = skip_ws(src, j); assert src[j] == ','
                s2, j = concat(src, j + 1)
                key = (s1, s2)
            if key not in seen:
                seen[key] = { 'id': key[0], 'plural': key[1], 'where': f, 'refs': [] }
                out.append(seen[key])
            seen[key]['refs'].append(ref)
    menu = os.path.join(root, 'root/usr/share/luci/menu.d/luci-app-detour.json')
    mtext = open(menu, encoding='utf-8').read()
    for k, v in json.loads(mtext).items():
        t = v.get('title')
        if not t: continue
        at = mtext.find('"title": ' + json.dumps(t, ensure_ascii=False))
        ref = 'root/usr/share/luci/menu.d/luci-app-detour.json:%d' % (mtext.count('\n', 0, at) + 1 if at >= 0 else 1)
        if (t, None) not in seen:
            seen[(t, None)] = { 'id': t, 'plural': None, 'where': 'menu', 'refs': [] }
            out.append(seen[(t, None)])
        seen[(t, None)]['refs'].append(ref)
    return out

def extract_ucode(root):
    """_('…') in the detour package's daemon and ucode modules (the messages sent to people)"""
    out, seen = [], {}
    mods = os.path.join(root, 'root/usr/share/ucode/detour')
    files = [ os.path.join(root, 'root/usr/sbin/detourd') ] + [ os.path.join(mods, f) for f in sorted(os.listdir(mods)) if f.endswith('.uc') and f != 'i18n.uc' ]
    for path in files:
        src = open(path, encoding='utf-8').read()
        for m in re.finditer(r'(?<![\w.])_\(', src):
            s, _ = concat(src, m.end())
            if s is None or s in seen: continue
            seen[s] = True
            out.append({'id': s, 'plural': None, 'where': os.path.basename(path)})
    return out

if __name__ == '__main__':
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(extract_ucode(sys.argv[2]) if sys.argv[1] == '--ucode' else extract(sys.argv[1]), ensure_ascii=False, indent=1))
