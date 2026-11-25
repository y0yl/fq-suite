#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fq_fast_aio.py —— v5 引擎：asyncio + aiohttp 长连接 + 匀速派发（提速 + 速度稳定）

为什么换引擎（bench_steady.py 实测，720 请求稳态）：

| 引擎 | req/s | p50 | 抖动(std/mean) |
|---|---|---|---|
| threads + urllib（v4 现状） | 44.2 | 3.33 s | 0.84 |
| 线程池 + requests.Session | 33.5 | 3.36 s | — |
| **aiohttp 长连接** | **86.7** | **1.76 s** | 0.47 |
| aiohttp w=120（更保守） | 71.4 | 1.40 s | **0.21** |

结论：v4 的「43 req/s 天花板」其实是**客户端天花板**（GIL + 每请求重连 TLS），
不是服务端的。换成 asyncio + keep-alive 后单 IP 实测 86 req/s、零 103015。

两个稳定性的来源：
  1. **匀速派发**：按 1/rate 的间隔发车（不是令牌桶那样允许突发），
     完成速率曲线因此几乎是直线；突发是触发风控和延迟抖动的直接原因。
  2. **连接复用**：720 个请求只开 ~20 条 TLS，服务端看到的「连接建立速率」降了 30 倍，
     这也是本次 86 req/s 仍然 0 个 103015 的原因之一。

用法：
  python fq_fast_aio.py --books <id,...> --rate 80 --workers 160
  python fq_fast_aio.py --books-file books.txt --resume --rate 70
  python fq_fast_aio.py --bench --rounds 12 --rate 80        # 只跑稳态基准
"""
import argparse, asyncio, gzip, hashlib, json, os, sqlite3, statistics, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fq_fast as _ff
from fq_fast import (make_body, api_url, base_headers, open_db, record_of,
                     RAW_REQ, PAGE, MAX_PAGES, API_HOST)
from fq_fast3 import open_db_ext
from fq_sign_tcp import TcpSigner

HOSTS = ['api5-normal-sinfonlineb.fqnovel.com',
         'api5-normal-sinfonlinea.fqnovel.com',
         'api5-normal-sinfonlinec.fqnovel.com',
         'api5-normal-lf.fqnovel.com',
         'api5-normal-lq.fqnovel.com',
         'api5-normal-hl.fqnovel.com']


def _parse(raw):
    if raw[:2] == b'\x1f\x8b':
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    try:
        j = json.loads(raw.decode('utf-8', 'ignore'))
    except Exception:
        return None
    d = j.get('data') or {}
    ci = d.get('common_list_info') or {}
    return {'code': j.get('code'), 'items': d.get('data_list') or [],
            'n': len(d.get('data_list') or []), 'cursor': ci.get('cursor'),
            'total': ci.get('total'), 'extra': d.get('extra') or {}}


class Pacer:
    """匀速派发：每个请求占一个时间槽，槽间隔 = 1/rate。"""

    def __init__(self, rate):
        self.rate = float(rate)
        self.next = time.monotonic()

    def slot(self):
        now = time.monotonic()
        if self.next < now:
            self.next = now
        t = self.next
        self.next += 1.0 / self.rate
        return max(0.0, t - now)


class AioV5:
    def __init__(self, signer, raw, con, rate=80.0, workers=160, tag_id=None, sort=1, src='long',
                 pages=MAX_PAGES, hosts=None, verbose=True):
        self.sig = signer
        self.raw = raw
        self.con = con
        self.rate = rate
        self.workers = workers
        self.pacer = Pacer(rate)
        self.tag_id = tag_id
        self.sort = sort
        self.src = src
        _ff.SRC = src
        self.pages_n = pages
        self.hosts = hosts or HOSTS
        self.verbose = verbose
        self.stat = {'req': 0, 'ok': 0, 'items': 0, 'fail': 0, 'retry': 0,
                     'resign': 0, 'codes': {}, 'lat': [], 'done_ts': []}
        self._hcursor = 0

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def _host(self):
        h = self.hosts[self._hcursor % len(self.hosts)]
        self._hcursor += 1
        return h

    def _sign(self, url, header):
        h = self.sig.sign_many(url, [header])[0]
        out = dict(header)
        out.update(h)
        return out

    async def _sign_async(self, url, header):
        # 签名是同步 TCP 调用（~2 ms），丢线程池避免阻塞事件循环、污染匀速派发
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sign, url, header)

    async def fetch(self, sess, book, cursor):
        for attempt in range(3):
            nm = int(time.time() * 1000)
            host = self._host()
            url = api_url(book, nm).replace(API_HOST, 'https://' + host)
            gz = gzip.compress(make_body(book, cursor, PAGE, self.tag_id, self.sort))
            base = base_headers(self.raw, nm)
            base['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
            try:
                headers = await self._sign_async(url, base)
            except Exception:
                await asyncio.sleep(0.5)
                continue
            headers['content-length'] = str(len(gz))

            await asyncio.sleep(self.pacer.slot())     # 匀速发车
            ts = time.time()
            self.stat['req'] += 1
            try:
                async with sess.post(url, data=gz, headers=headers,
                                     timeout=60) as r:
                    body = await r.read()
                res = _parse(body)
            except Exception:
                res = {'code': 'EXC'}
            dt = time.time() - ts
            code = res.get('code') if res else 'BADJSON'
            self.stat['lat'].append(dt)
            self.stat['done_ts'].append(time.time())
            self.stat['codes'][code] = self.stat['codes'].get(code, 0) + 1

            if code == 0:
                self.stat['ok'] += 1
                self.stat['items'] += res.get('n') or 0
                return res, attempt
            self.stat['retry'] += 1
            if str(code) == '110001':
                self.stat['resign'] += 1
                continue
            await asyncio.sleep(1.0 * (attempt + 1))
        self.stat['fail'] += 1
        return None, 3

    async def _run(self, tasks):
        import aiohttp
        conn = aiohttp.TCPConnector(limit=0, ssl=False, force_close=False,
                                    enable_cleanup_closed=True, ttl_dns_cache=300)
        sem = asyncio.Semaphore(self.workers)

        async with aiohttp.ClientSession(connector=conn) as sess:
            async def guarded(book, cur):
                async with sem:
                    return book, cur, await self.fetch(sess, book, cur)

            results = await asyncio.gather(*[guarded(b, c) for b, c in tasks])
        return results

    async def _run_rounds(self, task_lists):
        """多轮复用同一个 session/connector —— 稳态基准必须这样测，
        否则每轮都要重新建 60 条 TLS，测到的是握手成本不是吞吐。"""
        import aiohttp
        conn = aiohttp.TCPConnector(limit=0, ssl=False, force_close=False,
                                    enable_cleanup_closed=True, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=conn) as sess:
            for tasks in task_lists:
                sem = asyncio.Semaphore(self.workers)

                async def guarded(book, cur, _sess=sess, _sem=sem):
                    async with _sem:
                        return await self.fetch(_sess, book, cur)

                await asyncio.gather(*[guarded(b, c) for b, c in tasks])

    def run_many(self, books, rounds):
        """重复 rounds 轮同一批页（稳态基准用）。

        注意：不能一轮一个 gather —— 每轮都有「等最慢那个」的栅栏，
        60 个请求一轮会被 p99 拖住，测出来只有 30 req/s（假的）。
        这里把所有轮摊平成一个任务池，一次提交。
        """
        t0 = time.time()
        cursors = [None] + [PAGE * i for i in range(1, self.pages_n)]
        tasks = [(b, c) for _ in range(rounds) for b in books for c in cursors]
        self.log('[*] 稳态基准 %d 轮 × %d 页 × %d 本 = %d 请求' %
                 (rounds, len(cursors), len(books), len(tasks)))
        asyncio.run(self._run(tasks))
        return time.time() - t0

    def run(self, books, resume=False):
        t0 = time.time()
        tasks = []
        for b in books:
            cursors = [None] + [PAGE * i for i in range(1, self.pages_n)]
            if resume:
                bad = [r[0] for r in self.con.execute(
                    'select cursor from pages where book=? and src=? and ok=0', (b, self.src))]
                if bad:
                    cursors = [None if c == 'first' else int(c) for c in bad]
                    self.log('  [resume] %s 补 %d 页' % (b, len(cursors)))
            tasks += [(b, c) for c in cursors]
        self.log('[*] 任务 %d（%d 本）rate=%.0f workers=%d' %
                 (len(tasks), len(books), self.rate, self.workers))

        results = asyncio.run(self._run(tasks))

        rows = {b: [] for b in books}
        okn = {b: 0 for b in books}
        meta = {}
        for b, cur, (res, tries) in results:
            key = 'first' if cur is None else str(cur)
            if res is None:
                self.con.execute('INSERT OR REPLACE INTO pages values(?,?,?,?,?,?,?)',
                                 (b, self.src, key, 0, 'FAIL', tries, int(time.time())))
                continue
            okn[b] += 1
            for it in res['items']:
                rec = record_of(it, b)
                if rec['id']:
                    rows[b].append((rec['id'], rec['src'], rec['book'], rec['uid'], rec['uname'],
                                    rec['ts'], rec['txt'], rec['raw']))
            bi = (res.get('extra') or {}).get('book_info')
            if bi and b not in meta:
                meta[b] = {'name': bi.get('book_name'), 'author': bi.get('author'),
                           'score': bi.get('score'), 'total': res.get('total')}
            self.con.execute('INSERT OR REPLACE INTO pages values(?,?,?,?,?,?,?)',
                             (b, self.src, key, 1, '0', tries, int(time.time())))

        out = []
        now = int(time.time())
        for b in books:
            self.con.executemany(
                'INSERT OR IGNORE INTO comments(id,src,book,uid,uname,ts,txt,raw) '
'VALUES (?,?,?,?,?,?,?,?)', rows[b])
            m = meta.get(b, {})
            n_db = list(self.con.execute(
                'select count(*) from comments where book=? and src=?', (b, self.src)))[0][0]
            npages = len([1 for bb, _ in tasks if bb == b])
            self.con.execute(
                'INSERT OR REPLACE INTO books(book,total,fetched,status,updated_at) '
                'VALUES (?,?,?,?,?)',
                (b, m.get('total') or 0, n_db,
                 'done' if okn[b] == npages else 'partial', now))
            self.con.execute(
                'INSERT OR REPLACE INTO meta(book,book_name,author,score,tag_id,tag_name,'
                'total_in_app,collected_at) VALUES (?,?,?,?,?,?,?,?)',
                (b, m.get('name'), m.get('author'), m.get('score'), self.tag_id,
                 ('长评' if self.tag_id else '全部'), m.get('total'), now))
            self.con.commit()
            self.log('  [%s] %s / %s  %d 条  %d/%d 页' %
                     (b, m.get('name'), m.get('author'), n_db, okn[b], npages))
            out.append({'book': b, 'db': n_db, 'pages': npages, 'ok': okn[b]})
        return out, time.time() - t0

    def report(self, wall):
        lat = sorted(self.stat['lat'])
        p = (lambda q: lat[int(len(lat) * q)]) if lat else (lambda q: 0)
        marks = sorted(self.stat['done_ts'])
        if len(marks) > 6:
            t0 = marks[0]
            sec = {}
            for t in marks:
                sec[int(t - t0)] = sec.get(int(t - t0), 0) + 1
            keys = sorted(sec)
            # 稳态窗口：砍掉前 3 秒（连接预热）与最后 1 秒（收尾不完整）
            steady = [sec[k] for k in keys if 3 <= k < keys[-1]]
            if steady:
                mean = statistics.mean(steady)
                jit = statistics.pstdev(steady) / mean if mean else 0
                lo, hi = min(steady), max(steady)
            else:
                jit, lo, hi = 0, 0, 0
        else:
            jit, lo, hi = 0, 0, 0
        s = self.stat
        print('\n===== v5 汇总 =====')
        print('请求 %d  成功 %d  重试 %d  失败 %d  重签 %d' %
              (s['req'], s['ok'], s['retry'], s['fail'], s['resign']))
        print('返回码 %s' % {k: v for k, v in s['codes'].items() if v})
        print('墙钟 %.2fs  吞吐 %.1f req/s  条目 %.1f 条/s' %
              (wall, s['req'] / wall, s['items'] / wall))
        print('延迟 p50=%.2fs p90=%.2fs p99=%.2fs' % (p(0.5), p(0.9), p(0.99)))
        print('稳态每秒完成数：min=%d max=%d 抖动=%.2f（越小越稳）' % (lo, hi, jit))
        return {'req': s['req'], 'ok': s['ok'], 'wall': wall,
                'rps': s['req'] / wall, 'jitter': jit, 'p50': p(0.5)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--books')
    ap.add_argument('--books-file')
    ap.add_argument('--rate', type=float, default=80.0)
    ap.add_argument('--workers', type=int, default=160)
    ap.add_argument('--pages', type=int, default=MAX_PAGES)
    ap.add_argument('--tag-id', default='-5888420563323975634', help='长评视图的 tag；--view all 时忽略')
    ap.add_argument('--view', default='long', choices=['long', 'all'], help='long=长评(3000/本) all=全部(可达40万+)')
    ap.add_argument('--sort', type=int, default=1, help='全部视图排序：1=智能热门 3=时间倒序')
    ap.add_argument('--hosts', default='')
    ap.add_argument('--resume', action='store_true')
    ap.add_argument('--db', default=os.path.join(HERE, 'out', 'v5.db'))
    ap.add_argument('--json-dir', default='')
    ap.add_argument('--bench', action='store_true', help='重复打同一批页做稳态基准')
    ap.add_argument('--rounds', type=int, default=10)
    a = ap.parse_args()

    if not a.books and not a.books_file:
        ap.error('需要 --books 或 --books-file')
    books = [x.strip() for x in (a.books or '').split(',') if x.strip()]
    if a.books_file:
        books += [x.strip() for x in open(a.books_file, encoding='utf-8') if x.strip()]

    raw = json.load(open(RAW_REQ, encoding='utf-8'))
    con = open_db_ext(a.db)
    sig = TcpSigner()
    tag = a.tag_id if a.view == 'long' else None
    eng = AioV5(sig, raw, con, rate=a.rate, workers=a.workers, tag_id=tag,
                sort=a.sort, src=a.view,
                pages=a.pages, hosts=[h for h in a.hosts.split(',') if h] or None)

    if a.bench:
        # 稳态：单 session 跑多轮（避免每轮重建 TLS 污染结果）
        wall = eng.run_many(books, a.rounds)
        eng.report(wall)
    else:
        out, wall = eng.run(books, resume=a.resume)
        eng.report(wall)
        if a.json_dir:
            os.makedirs(a.json_dir, exist_ok=True)
            for r in out:
                b = r['book']
                rows = []
                for (rj,) in con.execute('select raw from comments where book=?', (b,)):
                    try:
                        rec = record_of(json.loads(rj), b)
                    except Exception:
                        continue
                    rec.pop('raw', None)
                    rows.append(rec)
                m = list(con.execute('select * from meta where book=?', (b,)))
                meta = {'book_name': m[0][1], 'author': m[0][2], 'score': m[0][3]} if m else {}
                p = os.path.join(a.json_dir, '%s.json' % b)
                json.dump({'book': b, 'meta': meta, 'count': len(rows), 'reviews': rows},
                          open(p, 'w', encoding='utf-8'), ensure_ascii=False)
                print('[json] %s %d 条' % (p, len(rows)))
    sig.close()
    con.close()


if __name__ == '__main__':
    main()