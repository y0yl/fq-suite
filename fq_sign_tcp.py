#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fq_sign_tcp.py —— 改造版 APK 的签名客户端（替代 frida 借签名）

改造后的 APK（work\\patched_signed.apk）内置 com.dragon.sign.SignServer：
  · 随 App 进程启动，监听 127.0.0.1:27043
  · 直接调用 NetworkParams.tryAddSecurityFactor（编译进 dex，不再需要 frida）
  · 行分隔 JSON 协议：{"url":u,"batch":[{h:v},...]} -> {"ok":true,"h":[{...},...]}

本模块提供与 fq_fast.Signer 完全一致的接口（sign_many/close），可直接替换：
    from fq_sign_tcp import TcpSigner as Signer

前置：adb forward tcp:27043 tcp:27043，且 App 里的服务已启动
      adb shell am start-foreground-service -n com.dragon.read/com.dragon.sign.SignServer

自检：python fq_sign_tcp.py --selftest
"""
import argparse, gzip, hashlib, json, os, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
_ADB_LOCAL = os.path.join(HERE, 'tools', 'platform-tools', 'adb.exe')
ADB = os.environ.get('ADB') or (_ADB_LOCAL if os.path.exists(_ADB_LOCAL) else 'adb')
PKG = 'com.dragon.read'
SVC = 'com.dragon.sign.SignServer'


class _Conn:
    """一条到 App 内签名服务的连接（带互斥，协议是行分隔 JSON，不能并发写）。"""

    def __init__(self, sock):
        self.sock = sock
        self.rf = sock.makefile('rwb')
        self.lock = threading.Lock()

    def call(self, obj, timeout=120):
        with self.lock:
            self.rf.write((json.dumps(obj, ensure_ascii=False) + '\n').encode('utf-8'))
            self.rf.flush()
            line = self.rf.readline()
        if not line:
            raise ConnectionError('empty response')
        return json.loads(line)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class TcpSigner:
    """签名客户端。pool 条连接并行（App 侧每个连接一个线程，native 签名本身可并发）。

    线程安全：sign_many 可被多线程同时调用，内部按连接互斥 + 轮转。
    """

    def __init__(self, host='127.0.0.1', port=27043, adb=ADB, autostart=True, pool=6):
        self.host, self.port, self.adb = host, port, adb
        self.pool_size = max(1, pool)
        self.conns = []
        self.rr = 0
        self.reconnects = 0
        self._init_lock = threading.Lock()
        if autostart:
            self.ensure_forward()
        self.connect()

    # ---------------------------------------------------------------- setup
    def ensure_forward(self):
        out = subprocess.run([self.adb, 'forward', '--list'], capture_output=True, text=True).stdout or ''
        if ('tcp:%d' % self.port) not in out:
            subprocess.run([self.adb, 'forward', 'tcp:%d' % self.port, 'tcp:%d' % self.port],
                           capture_output=True, text=True)

    def app_alive(self):
        p = subprocess.run([self.adb, 'shell', 'pidof', PKG], capture_output=True, text=True)
        return bool((p.stdout or '').strip())

    def start_service(self):
        subprocess.run([self.adb, 'shell', 'am', 'start-foreground-service', '-n',
                        '%s/%s' % (PKG, SVC)], capture_output=True, text=True)

    def _open_one(self):
        s = socket.create_connection((self.host, self.port), timeout=10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(120)
        c = _Conn(s)
        if not c.call({'ping': 1}).get('ok'):
            c.close()
            raise OSError('ping failed')
        return c

    def connect(self, tries=40):
        with self._init_lock:
            while len(self.conns) < self.pool_size:
                for i in range(tries):
                    try:
                        if not self.app_alive():
                            self.start_service()
                        self.conns.append(self._open_one())
                        break
                    except OSError:
                        time.sleep(0.5)
                else:
                    raise RuntimeError(
                        '签名服务不可达 %s:%d（App 未运行 / 服务未启动 / adb forward 丢失）'
                        % (self.host, self.port))
            return True

    def _pick(self):
        with self._init_lock:
            self.rr = (self.rr + 1) % len(self.conns)
            return self.conns[self.rr]

    def _reconnect(self, dead):
        with self._init_lock:
            if dead in self.conns:
                self.conns.remove(dead)
            self.reconnects += 1
            try:
                dead.close()
            except Exception:
                pass
            while True:
                try:
                    if not self.app_alive():
                        self.start_service()
                    self.conns.append(self._open_one())
                    return
                except OSError:
                    time.sleep(0.5)

    # ---------------------------------------------------------------- api
    def sign_many(self, url, header_list):
        """header_list: List[dict] -> List[dict]（6 个签名头）"""
        if not self.conns:
            self.connect()
        req = {'url': url, 'batch': header_list}
        for attempt in (0, 1):
            c = self._pick()
            try:
                r = c.call(req)
            except Exception:
                self._reconnect(c)     # 连接坏了（App 被杀 / 服务重启）→ 换一条重试
                if attempt:
                    raise
                continue
            if not r.get('ok'):
                raise RuntimeError('sign failed: %s' % (r.get('err'),))
            return r['h']
        raise RuntimeError('sign failed after reconnect')

    def close(self):
        for c in list(self.conns):
            try:
                c.close()
            except Exception:
                pass
        self.conns = []


def selftest():
    from fq_fast import make_body, api_url, base_headers, http_post, PAGE
    raw = json.load(open(os.path.join(HERE, 'out', 'raw_req.json'), encoding='utf-8'))
    book = '7143038691944959011'
    nm = int(time.time() * 1000)
    url = api_url(book, nm)
    gz = gzip.compress(make_body(book, 50, PAGE, '-5888420563323975634'))
    h = base_headers(raw, nm)
    h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()

    s = TcpSigner()
    print('[+] connected, ping ok')
    t0 = time.time()
    got = s.sign_many(url, [h])[0]
    print('[+] sign 1 in %.1f ms' % ((time.time() - t0) * 1000))
    for k, v in got.items():
        print('    %-12s %s' % (k, v[:64] + ('...' if len(v) > 64 else '')))

    n = 300
    t0 = time.time()
    out = s.sign_many(url, [h] * n)
    dt = time.time() - t0
    print('[+] batch %d in %.2fs  %.0f sign/s  (recv=%d)' % (n, dt, n / dt, len(out)))

    f = dict(h)
    f.update(got)
    f['content-length'] = str(len(gz))
    r = http_post(url, f, gz)
    print('[+] live request: code=%s n=%s total=%s' % (r.get('code'), r.get('n'), r.get('total')))
    s.close()


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        selftest()
    else:
        ap.print_help()