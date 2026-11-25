#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_bind.py —— 签名到底绑定什么？可变面探测

上一轮 probe_sigset.py 已确认：
  · 6 个签名头缺一不可（少一个 → 103001）
  · 签名输入只需 url + x-ss-stub，业务头不参与（B2）
  · 换 URL 里的 book id 仍然通过（C2）；换 _rticket 失败（C3）

这轮把「可变面」逐项钉死：哪些改动能过、哪些不能过。
直接影响：能否换出口 IP / 换 Host / 随机化 UA / 复用签名。

用法：python probe_bind.py
"""
import gzip, hashlib, json, os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fq_fast import Signer, make_body, api_url, base_headers, http_post, PAGE  # noqa

BOOK = '7143038691944959011'
BOOK2 = '7276384138653862966'
TAG = '-5888420563323975634'
RAW = json.load(open(os.path.join(HERE, 'out', 'raw_req.json'), encoding='utf-8'))


def prepare(sig, book=BOOK, cursor=50):
    nm = int(time.time() * 1000)
    url = api_url(book, nm)
    gz = gzip.compress(make_body(book, cursor, PAGE, TAG))
    h = base_headers(RAW, nm)
    h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
    sig_h = sig.sign_many(url, [h])[0]
    h.update(sig_h)
    h['content-length'] = str(len(gz))
    return nm, url, gz, h


def run(tag, url, gz, h, expect='0'):
    r = http_post(url, h, gz)
    code = r.get('code')
    flag = 'OK ' if str(code) == expect else 'XX '
    print('  %s%-34s code=%-8s n=%-3s' % (flag, tag, code, r.get('n')))
    return code


def main():
    sig = Signer()
    nm, url, gz, h = prepare(sig)
    print('=== 对照组 ===')
    run('T0 原样重放', url, gz, h)

    print('\n=== 请求头可变面（签名不变） ===')
    h2 = dict(h); h2['x-foo'] = 'bar'
    run('T1 加一个未签名头 x-foo', url, gz, h2)
    h2 = dict(h); h2['user-agent'] = h['user-agent'].replace('25102RKBEC', 'MI 9')
    run('T2 改 user-agent', url, gz, h2)
    h2 = dict(h); h2['cookie'] = h['cookie'].split(';')[0] + '; extra=1'
    run('T3 改 cookie', url, gz, h2)
    h2 = dict(h); h2.pop('x-reading-request', None)
    run('T4 删 x-reading-request', url, gz, h2)
    h2 = dict(h); h2['x-reading-request'] = '%d-%d' % (nm, 1)
    run('T5 改 x-reading-request 后段', url, gz, h2)
    h2 = dict(h); h2['x-ss-req-ticket'] = str(nm + 5000)
    run('T6 改 x-ss-req-ticket', url, gz, h2)
    h2 = dict(h); h2['x-vc-bdturing-sdk-version'] = '9.9.9'
    run('T7 改 turing sdk 版本', url, gz, h2)

    print('\n=== URL 可变面（签名不变，body 不变） ===')
    for tag, u in [('T8 换 book path', api_url(BOOK2, nm)),
                   ('T9 换 _rticket +111', api_url(BOOK, nm + 111)),
                   ('T10 换 _rticket +60000', api_url(BOOK, nm + 60000)),
                   ('T11 换 Host: api5-normal-sinfonlinec',
                    api_url(BOOK, nm).replace('sinfonlineb', 'sinfonlinec')),
                   ('T12 换 Host: api5-normal-lf',
                    api_url(BOOK, nm).replace('sinfonlineb', 'lf')),
                   ('T13 加 query 参数 foo=1', api_url(BOOK, nm) + '&foo=1'),
                   ('T14 删 klink_egdi', api_url(BOOK, nm).replace(
                       '&klink_egdi=AAJRrFTzYhQXuJlvbee-x_Ad_67d9BXcfkoFT3lahBPoe15b19EZf-4u', '')),
                   ]:
        run(tag, u, gz, h)

    print('\n=== 时间窗（同一签名） ===')
    for wait in (30, 90, 300):
        time.sleep(wait if wait == 30 else wait - 30)
        run('T15 +%ds 重放' % wait, url, gz, h)

    sig.close()


if __name__ == '__main__':
    main()