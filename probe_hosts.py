#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_hosts.py —— 找可用前端域名（签名不绑 Host，一份签名扫全部候选）

已确认：改 Host 不影响校验（T11/T12）。所以一次签名可以横扫一批候选域名，
只要返回 code=0 就是可用前端 —— 前端越多，单 IP 的 50 req/s 天花板就能摊薄。

用法：python probe_hosts.py
"""
import gzip, hashlib, json, os, socket, sys, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fq_fast import make_body, api_url, base_headers, http_post, PAGE, API_HOST  # noqa
from fq_sign_tcp import TcpSigner

BOOK = '7143038691944959011'
TAG = '-5888420563323975634'
RAW = json.load(open(os.path.join(HERE, 'out', 'raw_req.json'), encoding='utf-8'))

CANDS = [
    'api5-normal-sinfonlineb.fqnovel.com',
    'api5-normal-sinfonlinea.fqnovel.com',
    'api5-normal-sinfonlinec.fqnovel.com',
    'api5-normal-sinfonlined.fqnovel.com',
    'api5-normal-lf.fqnovel.com',
    'api5-normal-lq.fqnovel.com',
    'api5-normal-hl.fqnovel.com',
    'api5-normal-c-lf.fqnovel.com',
    'api5-normal-c-lq.fqnovel.com',
    'api5-normal-c-hl.fqnovel.com',
    'api5-normal-sinfonlineb.fqnovel.com',
    'api-normal-sinfonlineb.fqnovel.com',
    'api5-normal-sinfonlineb.fqnovelcdn.com',
    'api5-normal-sinfonlineb.amemv.com',
]


def dns(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def main():
    sig = TcpSigner()
    nm = int(time.time() * 1000)
    gz = gzip.compress(make_body(BOOK, 50, PAGE, TAG))
    h = base_headers(RAW, nm)
    h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
    url0 = api_url(BOOK, nm)
    sig_h = sig.sign_many(url0, [h])[0]
    full = dict(h)
    full.update(sig_h)
    full['content-length'] = str(len(gz))
    print('[+] 一份签名到手，开始扫 %d 个候选域名' % len(CANDS))

    def one(host):
        ip = dns(host)
        if not ip:
            return host, None, 'DNS_FAIL', None
        url = url0.replace(API_HOST, 'https://' + host)
        t0 = time.time()
        r = http_post(url, dict(full), gz)
        return host, ip, r.get('code'), round(time.time() - t0, 2)

    ok = []
    with ThreadPoolExecutor(max_workers=len(CANDS)) as ex:
        for host, ip, code, dt in ex.map(one, CANDS):
            mark = 'OK ' if code == 0 else '   '
            print('  %s%-42s %-16s code=%-8s %ss' % (mark, host, ip or '-', code, dt))
            if code == 0:
                ok.append(host)
    print('\n可用前端 %d 个：' % len(ok))
    for h in ok:
        print('  ' + h)
    sig.close()


if __name__ == '__main__':
    main()