#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
discover_books.py —— 书单发现（多来源，全部不依赖签名）

思路：签名不绑 URL path（probe_bind 已验证），所以能签任意接口；但接口参数要逆。
本脚本先用**零成本来源**把 book_id 铺开：

  1. 番茄 web 站（fanqienovel.com）榜单/搜索页 HTML 里的 /page/<book_id> 链接；
  2. 备用：把已知 book_id 的「相似推荐」接口当种子扩散（需要签名，走 TCP 签名机）。

产出 out/books_candidates.txt（一行一个 book_id），再用 commentapi 校验哪些有长评。

用法：
  python discover_books.py --pages 8 --out out\\books_candidates.txt
  python discover_books.py --validate 30           # 只校验已有候选里前 N 个
"""
import argparse, gzip, hashlib, json, os, re, ssl, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'out')
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/124.0 Safari/537.36')

WEB_PAGES = [
    'https://fanqienovel.com/rank',
    'https://fanqienovel.com/library',
    'https://fanqienovel.com/library/1_1_1',
    'https://fanqienovel.com/library/2_1_1',
    'https://fanqienovel.com/rank/1_2_1',
    'https://fanqienovel.com/rank/2_2_1',
    'https://fanqienovel.com/rank/3_2_1',
    'https://fanqienovel.com/search?q=%E7%8E%84%E5%B9%BB',
]

_C = ssl.create_default_context()
_C.check_hostname = False
_C.verify_mode = ssl.CERT_NONE


def fetch(url, timeout=25):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept-Language': 'zh-CN,zh'})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_C) as r:
            return r.read().decode('utf-8', 'ignore')
    except Exception as e:
        print('   [!] %s -> %r' % (url, e))
        return ''


def ids_from_html(html):
    s = set()
    s |= set(re.findall(r'/page/(\d{15,20})', html))
    s |= set(re.findall(r'book_id["\']?\s*[:=]\s*["\']?(\d{15,20})', html))
    s |= set(re.findall(r'/reader/(\d{15,20})', html))
    return s


def validate(ids, tag_id='-5888420563323975634', limit=None):
    """用 commentapi 打一页，确认这本有长评 + 拿 total。"""
    sys.path.insert(0, HERE)
    from fq_sign_tcp import TcpSigner
    from fq_fast import make_body, api_url, base_headers, http_post, PAGE, RAW_REQ
    raw = json.load(open(RAW_REQ, encoding='utf-8'))
    sig = TcpSigner()
    ok = []
    todo = ids[:limit] if limit else ids
    for i, b in enumerate(todo):
        nm = int(time.time() * 1000)
        url = api_url(b, nm)
        gz = gzip.compress(make_body(b, None, PAGE, tag_id))
        h = base_headers(raw, nm)
        h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
        try:
            s = sig.sign_many(url, [h])[0]
            h.update(s)
            h['content-length'] = str(len(gz))
            r = http_post(url, h, gz)
            code = r.get('code')
            if code == 0:
                ok.append((b, r.get('total'), r.get('n')))
                print('  [ok]   %s total=%s n=%s' % (b, r.get('total'), r.get('n')))
            else:
                print('  [skip] %s code=%s' % (b, code))
        except Exception as e:
            print('  [err]  %s %r' % (b, e))
    sig.close()
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pages', type=int, default=0, help='抓多少个 web 页面（默认全部）')
    ap.add_argument('--out', default=os.path.join(OUT, 'books_candidates.txt'))
    ap.add_argument('--validate', type=int, default=0, help='校验前 N 个候选（0=不校验）')
    ap.add_argument('--seed-file', default='')
    a = ap.parse_args()

    os.makedirs(OUT, exist_ok=True)
    got = []
    seen = set()
    pages = WEB_PAGES[:a.pages] if a.pages else WEB_PAGES
    for u in pages:
        html = fetch(u)
        ids = ids_from_html(html)
        new = ids - seen
        seen |= ids
        print('[+] %-46s +%d  (累计 %d)' % (u.replace('https://fanqienovel.com', ''), len(new), len(seen)))

    if a.seed_file and os.path.exists(a.seed_file):
        for line in open(a.seed_file, encoding='utf-8'):
            b = line.strip()
            if b and b not in seen:
                seen.add(b)
                got.append(b)

    ids = sorted(seen, key=lambda x: -len(x)) or []
    if a.seed_file and os.path.exists(a.seed_file):
        for line in open(a.seed_file, encoding='utf-8'):
            b = line.strip()
            if b and b not in ids:
                ids.append(b)
    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(ids) + ('\n' if ids else ''))
    print('\n[=] 候选 %d 个 -> %s' % (len(ids), a.out))
    for b in ids[:10]:
        print('    ' + b)

    if a.validate and ids:
        print('\n[*] 校验前 %d 个（commentapi 长评）' % a.validate)
        ok = validate(ids, limit=a.validate)
        vp = os.path.join(OUT, 'books_valid.txt')
        with open(vp, 'w', encoding='utf-8') as f:
            for b, total, n in ok:
                f.write('%s\t%s\n' % (b, total))
        print('[=] 可用 %d 本 -> %s' % (len(ok), vp))


if __name__ == '__main__':
    main()