#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bench_steady.py —— 稳态吞吐对比（这才是「提速 + 速度稳定」的度量口径）

之前的 bench_net.py 只发一波（180 请求）就收工，测的是「单波墙钟 ≈ p50」，
测不出引擎的真实上限。这里改成：同一批 URL 连打 R 轮，测稳态 req/s 和抖动。

对比引擎：
  threads   —— 现状：每个请求一个线程 + urllib（每请求重建 TLS）
  session    —— 固定 N 线程 + 每线程一个 requests.Session（keep-alive，线程常驻）
  aiohttp    —— asyncio + 常驻连接池
  multi      —— K 个进程 × aiohttp（绕开 GIL）

指标：墙钟、req/s、p50/p95、**每秒完成数的抖动（std/mean）**、错误码分布。
抖动小 = 速度稳定；req/s 高 = 快。

用法：
  python bench_steady.py --rounds 10 --engine threads,session,aiohttp,multi
  python bench_steady.py --rounds 10 --hosts 1     # 单前端 vs 六前端
"""
import argparse, asyncio, gzip, hashlib, json, os, queue, statistics, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fq_fast import make_body, api_url, base_headers, http_post, PAGE, API_HOST  # noqa
from fq_sign_tcp import TcpSigner

BOOK = '7143038691944959011'
TAG = '-5888420563323975634'
RAW = json.load(open(os.path.join(HERE, 'out', 'raw_req.json'), encoding='utf-8'))

HOSTS_ALL = ['api5-normal-sinfonlineb.fqnovel.com',
             'api5-normal-sinfonlinea.fqnovel.com',
             'api5-normal-sinfonlinec.fqnovel.com',
             'api5-normal-lf.fqnovel.com',
             'api5-normal-lq.fqnovel.com',
             'api5-normal-hl.fqnovel.com']


def jobs(rounds, hosts):
    """签好 rounds × 60 个请求，按 host 轮转分配"""
    sig = TcpSigner()
    out = []
    t0 = time.time()
    cursors = [None] + [PAGE * i for i in range(1, 60)]
    for r in range(rounds):
        nm = int(time.time() * 1000) + r
        url0 = api_url(BOOK, nm)
        hjs, bodies = [], []
        for c in cursors:
            gz = gzip.compress(make_body(BOOK, c, PAGE, TAG))
            h = base_headers(RAW, nm)
            h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
            hjs.append(h)
            bodies.append(gz)
        sigs = sig.sign_many(url0, hjs)
        for i, (gz, h, s) in enumerate(zip(bodies, hjs, sigs)):
            host = hosts[i % len(hosts)]
            url = url0.replace(API_HOST, 'https://' + host)
            f = dict(h)
            f.update(s)
            f['content-length'] = str(len(gz))
            out.append((url, f, gz))
    print('  [sign] %d 个请求签名耗时 %.1fs' % (len(out), time.time() - t0))
    sig.close()
    return out


def summarize(name, wall, lat, codes, t0, t1):
    lat = sorted(lat)
    n = len(lat)
    p50 = lat[n // 2] if n else 0
    p95 = lat[int(n * 0.95)] if n else 0
    # 每秒完成数抖动
    sec = {}
    for ts in t1:
        sec[int(ts - t0)] = sec.get(int(ts - t0), 0) + 1
    keys = sorted(sec)
    if len(keys) > 4:
        # 去掉首尾两个桶：首桶含启动爬坡，尾桶不完整，都会污染「稳态抖动」
        counts = [sec[k] for k in keys[2:-1]]
        mean = statistics.mean(counts)
        jit = statistics.pstdev(counts) / mean if mean else 0
    else:
        jit = 0
    ok = codes.get(0, 0) + codes.get('0', 0)
    print('%-10s wall=%6.2fs  %5.1f req/s  ok=%d/%d  p50=%.2f p95=%.2f  jitter=%.2f  codes=%s'
          % (name, wall, n / wall if wall else 0, ok, n, p50, p95, jit,
             {k: v for k, v in codes.items() if v}))


def parse(raw):
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    try:
        j = json.loads(raw.decode('utf-8', 'ignore'))
        return j.get('code')
    except Exception:
        return 'BADJSON'


# ---------------------------------------------------------------- engines
def eng_threads(js, workers):
    codes, lat, done = {}, [], []
    t0 = time.time()

    def one(j):
        r = http_post(j[0], j[1], j[2])
        return r.get('code'), r.get('dt', 0)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for code, dt in ex.map(one, js):
            codes[code] = codes.get(code, 0) + 1
            lat.append(dt)
            done.append(time.time())
    return time.time() - t0, lat, codes, t0, done


def eng_session(js, workers):
    import requests
    q = queue.Queue()
    for j in js:
        q.put(j)
    codes, lat, done = {}, [], []
    lock = threading.Lock()
    t0 = time.time()

    def worker():
        s = requests.Session()
        ad = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1, max_retries=0)
        s.mount('https://', ad)
        s.verify = False
        while True:
            try:
                url, h, gz = q.get_nowait()
            except queue.Empty:
                return
            ts = time.time()
            try:
                r = s.post(url, data=gz, headers=h, timeout=60)
                code = parse(r.content)
            except Exception:
                code = 'EXC'
            with lock:
                codes[code] = codes.get(code, 0) + 1
                lat.append(time.time() - ts)
                done.append(time.time())

    ths = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    return time.time() - t0, lat, codes, t0, done


def eng_aiohttp(js, workers, procs=1):
    import aiohttp

    async def run(sub):
        conn = aiohttp.TCPConnector(limit=0, ssl=False, force_close=False, enable_cleanup_closed=True)
        sem = asyncio.Semaphore(workers)
        codes, lat, done = {}, [], []
        async with aiohttp.ClientSession(connector=conn, headers={}) as s:
            async def one(j):
                url, h, gz = j
                async with sem:
                    ts = time.time()
                    try:
                        async with s.post(url, data=gz, headers=h, timeout=aiohttp.ClientTimeout(total=60)) as r:
                            body = await r.read()
                        code = parse(body)
                    except Exception:
                        code = 'EXC'
                    lat.append(time.time() - ts)
                    done.append(time.time())
                    codes[code] = codes.get(code, 0) + 1
            await asyncio.gather(*[one(j) for j in sub])
        return lat, codes, done

    t0 = time.time()
    lat, codes, done = asyncio.run(run(js))
    return time.time() - t0, lat, codes, t0, done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rounds', type=int, default=10)
    ap.add_argument('--workers', type=int, default=180)
    ap.add_argument('--hosts', type=int, default=6)
    ap.add_argument('--engine', default='threads,session,aiohttp')
    ap.add_argument('--repeat', type=int, default=1)
    a = ap.parse_args()

    hosts = HOSTS_ALL[:max(1, a.hosts)]
    print('[*] hosts=%d rounds=%d workers=%d' % (len(hosts), a.rounds, a.workers))
    for h in hosts:
        print('    ' + h)
    js = jobs(a.rounds, hosts)
    print('[*] 总请求 %d' % len(js))

    for name in a.engine.split(','):
        for rep in range(a.repeat):
            if name == 'threads':
                r = eng_threads(js, a.workers)
            elif name == 'session':
                r = eng_session(js, a.workers)
            elif name == 'aiohttp':
                r = eng_aiohttp(js, a.workers)
            else:
                print('  unknown engine', name)
                continue
            summarize(name if a.repeat == 1 else '%s#%d' % (name, rep + 1), *r)


if __name__ == '__main__':
    main()