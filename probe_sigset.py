#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_sigset.py —— 签名面（signature surface）矩阵实验

要回答的问题（直接决定能不能离线签名 / 能不能一签多用）：
  A. 6 个签名头里哪些是服务端真正校验的？（少一个就 110001 还是照过）
  B. 校验的最小签名输入是什么？（全部 header / 只有部分 / 只有 url）
  C. 签名是否绑定 URL 的 query（aid/rticket/cdid 等）？
  D. count 上限、响应体瘦身开关

用法：python probe_sigset.py
"""
import gzip, hashlib, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fq_fast import Signer, make_body, api_url, base_headers, http_post, PAGE, SIGKEYS  # noqa

BOOK = '7143038691944959011'
RAW = json.load(open(os.path.join(HERE, 'out', 'raw_req.json'), encoding='utf-8'))
TAG = '-5888420563323975634'


def build(sig, book=BOOK, cursor=50, tag=TAG, count=PAGE, sign_keys=None,
          url_book=None, strip_send=None):
    """返回 (url, headers, gzbody)"""
    nm = int(time.time() * 1000)
    url = api_url(url_book or book, nm)
    bh = base_headers(RAW, nm)
    gz = gzip.compress(make_body(book, cursor, count, tag))
    h = dict(bh)
    h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
    if sign_keys is not None:
        h = {k: v for k, v in h.items() if k.lower() in sign_keys}
    got = sig.sign_many(url, [h])[0]
    f = dict(h)
    f.update(got)
    if strip_send:
        for k in strip_send:
            f.pop(k, None)
            f.pop(k.lower(), None)
            f.pop(k.title(), None)
    f['content-length'] = str(len(gz))
    return url, f, gz


def send(url, h, gz):
    r = http_post(url, h, gz)
    return r.get('code'), r.get('n'), r.get('total'), round(r.get('dt', 0), 2)


def main():
    sig = Signer()
    print('=== A. 少头 / 只留部分头 ===')
    cases = [('S1 全 6 头(对照)', None),
             ('S2 去掉 x-medusa', [k for k in SIGKEYS if k != 'x-medusa']),
             ('S3 去掉 x-helios', [k for k in SIGKEYS if k != 'x-helios']),
             ('S4 去掉 x-ladon', [k for k in SIGKEYS if k != 'x-ladon']),
             ('S5 去掉 x-argus', [k for k in SIGKEYS if k != 'x-argus']),
             ('S6 去掉 x-gorgon', [k for k in SIGKEYS if k != 'x-gorgon']),
             ('S7 去掉 x-khronos', [k for k in SIGKEYS if k != 'x-khronos']),
             ('S8 只 x-khronos+x-gorgon', ['x-khronos', 'x-gorgon']),
             ('S9 只 x-khronos+x-argus', ['x-khronos', 'x-argus']),
             ('S10 只 x-khronos', ['x-khronos'])]
    for name, keys in cases:
        try:
            url, h, gz = build(sig, sign_keys=keys)
            c, n, t, dt = send(url, h, gz)
            print('  %-28s code=%-8s n=%-3s total=%-6s %ss' % (name, c, n, t, dt))
        except Exception as e:
            print('  %-28s EXC %r' % (name, e))
        time.sleep(0.4)

    print('\n=== B. 签名输入最小化（签名时只给部分 header，发送时补全） ===')
    for name, keys in [('B1 签名含全部业务头', None),
                       ('B2 签名只含签名头+x-ss-stub',
                        [k for k in SIGKEYS] + ['x-ss-stub']),
                       ('B3 签名只含 url+空 header', [])]:
        # B: 签名集合不同，但发送集合始终是「签名结果 + 完整业务头」
        nm = int(time.time() * 1000)
        url = api_url(BOOK, nm)
        gz = gzip.compress(make_body(BOOK, 50, PAGE, TAG))
        full = base_headers(RAW, nm)
        full['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
        if keys is None:
            sign_in = full
        else:
            sign_in = {k: v for k, v in full.items() if k.lower() in keys}
        got = sig.sign_many(url, [sign_in])[0]
        f = dict(full)
        f.update(got)
        f['content-length'] = str(len(gz))
        c, n, t, dt = send(url, f, gz)
        print('  %-30s code=%-8s n=%-3s %ss' % (name, c, n, dt))
        time.sleep(0.4)

    print('\n=== C. 签名是否绑定 URL query ===')
    # C1: 用 book A 的签名，发到 book B 的 URL（同 header）
    nm = int(time.time() * 1000)
    gz = gzip.compress(make_body(BOOK, 50, PAGE, TAG))
    h = base_headers(RAW, nm)
    h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
    urlA = api_url(BOOK, nm)
    got = sig.sign_many(urlA, [h])[0]
    f = dict(h); f.update(got); f['content-length'] = str(len(gz))
    for tag_, u in [('C1 同 URL 对照', urlA),
                    ('C2 换 book 的 URL', api_url('7276384138653862966', nm)),
                    ('C3 换 rticket', api_url(BOOK, nm + 111))]:
        c, n, t, dt = send(u, f, gz)
        print('  %-22s code=%-8s n=%-3s %ss' % (tag_, c, n, dt))
        time.sleep(0.4)

    print('\n=== D. count 上限 / 分页 ===')
    for cnt in (20, 50, 100, 200, 500):
        url, h, gz = build(sig, cursor=50, count=cnt)
        c, n, t, dt = send(url, h, gz)
        print('  count=%-4s code=%-8s n=%-3s total=%-6s' % (cnt, c, n, t))
        time.sleep(0.4)

    sig.close()


if __name__ == '__main__':
    main()