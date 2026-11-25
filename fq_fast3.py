#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fq_fast3.py —— v4 采集器：改造版 APK 内置签名服务 + 自适应限速 + 页级续跑

相对 v3（fq_fast2.py）的改动，全部为了「稳定性」和「长时间无人值守」：

1. 签名后端可切换：默认 `tcp`（改造 APK 的 127.0.0.1:27043，无 frida），
   也可 `frida` 回退。TCP 后端单连接实测 495 签/s，比 frida 的 450 签/s 还快，
   但没有 frida 会话、没有 houdini native invoke、没有注入痕迹。
2. 失败分型 + 自动处置（这是稳定性的核心）：
     · 103015 限流      → 触发降速（AIMD），退避后重发
     · 110001 签名不符  → 重签（body 变了或时间窗过），再发
     · EXC/BADJSON/5xx  → 重签重试
     · 连接被重置       → 换 keep-alive 连接
   每页最多 3 轮，失败游标写入 progress 表，`--resume` 只补失败页。
3. 全局限速器（token bucket）：目标 req/s 可调，降速/恢复自动，避免把 103015 打成一片。
4. 多 Host 轮转：实测 api5-normal-sinfonline{b,c} / api5-normal-lf 三个前端都收同一份签名
   （签名不绑 Host，只绑 query + x-ss-stub），可把 180 请求摊到 3 个前端，降低单前端风控压力。
5. 传输层：thread-local keep-alive 连接（requests.Session/pool=1），
   大并发下省掉每请求 TLS 握手；`--transport urllib` 可回退老路径做对照。

用法：
  python fq_fast3.py --books 7143038691944959011,7276384138653862966 --workers 180
  python fq_fast3.py --books-file books.txt --rate 40 --resume --db out\\v4.db
"""
import argparse, gzip, hashlib, json, os, sqlite3, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

import fq_fast as _ff
from fq_fast import (http_post, make_body, api_url, base_headers, open_db,
                     record_of, RAW_REQ, HERE, PAGE, MAX_PAGES, API_HOST)

HOSTS = ['api5-normal-sinfonlineb.fqnovel.com',
         'api5-normal-sinfonlinec.fqnovel.com',
         'api5-normal-lf.fqnovel.com']


# ---------------------------------------------------------------- 限速器
class RateLimiter:
    """token bucket + AIMD：成功缓慢提速，限流快速降速。线程安全。"""

    def __init__(self, rate=40.0, min_rate=4.0, max_rate=60.0):
        self.rate = float(rate)
        self.min_rate, self.max_rate = min_rate, max_rate
        self.tokens = float(rate)
        self.cap = float(rate)
        self.ts = time.time()
        self.lock = threading.Lock()
        self.ok_since = 0

    def acquire(self, n=1):
        while True:
            with self.lock:
                now = time.time()
                self.tokens = min(self.cap, self.tokens + (now - self.ts) * self.rate)
                self.ts = now
                if self.tokens >= n:
                    self.tokens -= n
                    return
                wait = (n - self.tokens) / self.rate
            time.sleep(min(wait, 1.0))

    def on_ok(self):
        with self.lock:
            self.ok_since += 1
            if self.ok_since >= 200:          # 每 200 个成功 +5%
                self.ok_since = 0
                self.rate = min(self.max_rate, self.rate * 1.05)
                self.cap = max(self.cap, self.rate)

    def on_limit(self, kind='103015'):
        with self.lock:
            self.ok_since = 0
            if kind == '103015':
                self.rate = max(self.min_rate, self.rate * 0.6)
            else:
                self.rate = max(self.min_rate, self.rate * 0.85)
            self.cap = self.rate
            self.tokens = 0.0


# ---------------------------------------------------------------- 传输层
class HttpClient:
    """thread-local keep-alive 连接。失败自动重建。"""

    def __init__(self, transport='session', timeout=60):
        self.transport = transport
        self.timeout = timeout
        self.tl = threading.local()

    def post(self, url, headers, body):
        if self.transport == 'urllib':
            return http_post(url, headers, body, timeout=self.timeout)
        s = getattr(self.tl, 'sess', None)
        if s is None:
            import requests
            s = requests.Session()
            ad = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=2,
                                              max_retries=0)
            s.mount('https://', ad)
            s.verify = False
            self.tl.sess = s
        t0 = time.time()
        try:
            r = s.post(url, data=body, headers=headers, timeout=self.timeout)
            raw = r.content
        except Exception as e:
            try:
                self.tl.sess = None
                s.close()
            except Exception:
                pass
            return {'code': 'EXC', 'n': 0, 'items': [], 'dt': time.time() - t0, 'err': repr(e)}
        dt = time.time() - t0
        if raw[:2] == b'\x1f\x8b':
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
        try:
            j = json.loads(raw.decode('utf-8', 'ignore'))
        except Exception:
            return {'code': 'BADJSON', 'n': 0, 'items': [], 'dt': dt,
                    'err': raw[:80].decode('utf-8', 'ignore')}
        d = j.get('data') or {}
        ci = d.get('common_list_info') or {}
        return {'code': j.get('code'), 'items': d.get('data_list') or [],
                'n': len(d.get('data_list') or []), 'cursor': ci.get('cursor'),
                'total': ci.get('total'), 'dt': dt, 'extra': d.get('extra') or {}}


# ---------------------------------------------------------------- 落库
EXT_SCHEMA = """
CREATE TABLE IF NOT EXISTS pages(
  book TEXT, src TEXT NOT NULL DEFAULT 'long', cursor TEXT, ok INT, code TEXT, tries INT, ts INT,
  PRIMARY KEY(book, src, cursor));
"""


def open_db_ext(path):
    con = open_db(path)
    con.executescript(EXT_SCHEMA)
    con.commit()
    return con


# ---------------------------------------------------------------- 采集
class V4:
    def __init__(self, signer, raw, con, workers=180, rate=40.0, tag_id=None, sort=1, src='long',
                 pages=MAX_PAGES, transport='session', hosts=None, verbose=True):
        self.sig = signer
        self.raw = raw
        self.con = con
        self.workers = workers
        self.rl = RateLimiter(rate)
        self.tag_id = tag_id
        self.sort = sort
        self.src = src
        _ff.SRC = src
        self.pages_n = pages
        self.http = HttpClient(transport)
        self.hosts = hosts or HOSTS
        self.verbose = verbose
        self.lock = threading.Lock()
        self.stat = {'req': 0, 'ok': 0, 'items': 0, 'fail': 0, 'retry': 0,
                     'codes': {}, 'lat': [], 'resign': 0}

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def _bump(self, key, n=1):
        with self.lock:
            self.stat[key] = self.stat.get(key, 0) + n

    def _code(self, code):
        with self.lock:
            self.stat['codes'][str(code)] = self.stat['codes'].get(str(code), 0) + 1

    # -- 一份 body 的完整请求（含重签重试）
    def fetch(self, book, cursor, url_host=None):
        url = None
        headers = None
        body = None
        for attempt in range(3):
            if headers is None:
                nm = int(time.time() * 1000)
                host = url_host or self.hosts[(book_hash(book) + attempt) % len(self.hosts)]
                url = api_url(book, nm).replace(API_HOST, 'https://' + host)
                body = make_body(book, cursor, PAGE, self.tag_id, self.sort)
                gz = gzip.compress(body)
                h = base_headers(self.raw, nm)
                h['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
                sig = self.sig.sign_many(url, [h])[0]
                headers = dict(h)
                headers.update(sig)
                headers['content-length'] = str(len(gz))
                body = gz
            self.rl.acquire()
            self._bump('req')
            r = self.http.post(url, headers, body)
            code = r.get('code')
            self._code(code)
            if r.get('dt'):
                with self.lock:
                    self.stat['lat'].append(r['dt'])
            if code == 0:
                self.rl.on_ok()
                self._bump('ok')
                self._bump('items', r.get('n') or 0)
                return r, attempt
            if str(code) == '103015':
                self.rl.on_limit('103015')
                self._bump('retry')
                time.sleep(1.2 * (attempt + 1))
                continue
            if str(code) == '110001':
                self.rl.on_limit('110001')
                self._bump('retry')
                self._bump('resign')
                headers = None          # 重签
                continue
            self._bump('retry')
            time.sleep(0.6 * (attempt + 1))
            if str(code) in ('EXC', 'BADJSON', '103001'):
                headers = None          # 重签 + 换连接
        self._bump('fail')
        return None, 3

    # -- 跨书全局池：所有书的页面任务一次性丢进同一个池（v3 的核心收益）
    def run_all(self, books, resume=False):
        t0 = time.time()
        tasks = []
        for b in books:
            cursors = [None] + [PAGE * i for i in range(1, self.pages_n)]
            if resume:
                bad = [row[0] for row in self.con.execute(
                    'select cursor from pages where book=? and src=? and ok=0', (b, self.src))]
                if bad:
                    cursors = [None if c == 'first' else int(c) for c in bad]
                    self.log('  [resume] %s 补 %d 页' % (b, len(cursors)))
            tasks += [(b, c) for c in cursors]
        self.log('[*] 任务 %d（%d 本 × %d 页）' % (len(tasks), len(books), self.pages_n))

        rows = {}
        meta = {}
        okn = {}
        for b in books:
            rows[b], okn[b] = [], 0
        with ThreadPoolExecutor(max_workers=max(1, min(self.workers, len(tasks)))) as ex:
            futs = {ex.submit(self.fetch, b, c): (b, c) for b, c in tasks}
            for f in as_completed(futs):
                b, cur = futs[f]
                r, tries = f.result()
                key = 'first' if cur is None else str(cur)
                if r is None:
                    self.con.execute('INSERT OR REPLACE INTO pages values(?,?,?,?,?,?,?)',
                                     (b, self.src, key, 0, 'FAIL', tries, int(time.time())))
                    continue
                okn[b] += 1
                for it in r['items']:
                    rec = record_of(it, b)
                    if rec['id']:
                        rows[b].append((rec['id'], rec['src'], rec['book'], rec['uid'], rec['uname'],
                                        rec['ts'], rec['txt'], rec['raw']))
                ex_ = r.get('extra') or {}
                bi = ex_.get('book_info')
                if bi and b not in meta:
                    meta[b] = {'name': bi.get('book_name'), 'author': bi.get('author'),
                               'score': bi.get('score'), 'total': r.get('total')}
                self.con.execute('INSERT OR REPLACE INTO pages values(?,?,?,?,?,?,?)',
                                 (b, self.src, key, 1, '0', tries, int(time.time())))

        out = []
        with self.lock:
            for b in books:
                self.con.executemany(
                    'INSERT OR IGNORE INTO comments(id,src,book,uid,uname,ts,txt,raw) '
'VALUES (?,?,?,?,?,?,?,?)', rows[b])
                m = meta.get(b, {})
                n_db = list(self.con.execute(
                    'select count(*) from comments where book=? and src=?', (b, self.src)))[0][0]
                total_pages = len([1 for bb, _ in tasks if bb == b])
                self.con.execute(
                    'INSERT OR REPLACE INTO books(book,total,fetched,status,updated_at) '
                    'VALUES (?,?,?,?,?)',
                    (b, m.get('total') or 0, n_db,
                     'done' if okn[b] == total_pages else 'partial', int(time.time())))
                self.con.execute(
                    'INSERT OR REPLACE INTO meta(book,book_name,author,score,tag_id,'
                    'tag_name,total_in_app,collected_at) VALUES (?,?,?,?,?,?,?,?)',
                    (b, m.get('name'), m.get('author'), m.get('score'),
                     self.tag_id, ('长评' if self.tag_id else '全部'), m.get('total'), int(time.time())))
                self.con.commit()
                self.log('  [%s] %s / %s  %d 条  %d/%d 页' %
                         (b, m.get('name'), m.get('author'), n_db, okn[b], total_pages))
                out.append({'book': b, 'db': n_db, 'pages_ok': okn[b],
                            'pages': total_pages, 'name': m.get('name')})
        return out, time.time() - t0

    def report(self, dt):
        lat = sorted(self.stat['lat'])
        p = lambda q: lat[int(len(lat) * q)] if lat else 0
        print('\n===== 汇总 =====')
        print('请求 %d  成功 %d  重试 %d  失败 %d  重签 %d' %
              (self.stat['req'], self.stat['ok'], self.stat['retry'], self.stat['fail'],
               self.stat['resign']))
        print('返回码分布 %s' % self.stat['codes'])
        print('延迟 p50=%.2fs p90=%.2fs p99=%.2fs' % (p(0.5), p(0.9), p(0.99)))
        print('总耗时 %.2fs  吞吐 %.1f 条/s  %.1f req/s  当前限速 %.1f req/s' %
              (dt, self.stat['items'] / dt if dt else 0,
               self.stat['req'] / dt if dt else 0, self.rl.rate))


def book_hash(b):
    try:
        return int(hashlib.md5(b.encode()).hexdigest()[:6], 16)
    except Exception:
        return 0


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--books')
    ap.add_argument('--books-file')
    ap.add_argument('--workers', type=int, default=180)
    ap.add_argument('--pages', type=int, default=MAX_PAGES)
    ap.add_argument('--rate', type=float, default=40.0, help='目标 req/s（自适应会浮动）')
    ap.add_argument('--tag-id', default='-5888420563323975634', help='长评视图的 tag；--view all 时忽略')
    ap.add_argument('--view', default='long', choices=['long', 'all'], help='long=长评(3000/本) all=全部(可达40万+)')
    ap.add_argument('--sort', type=int, default=1, help='全部视图排序：1=智能热门 3=时间倒序')
    ap.add_argument('--backend', default='tcp', choices=['tcp', 'frida'])
    ap.add_argument('--transport', default='urllib', choices=['session', 'urllib'])
    ap.add_argument('--hosts', default='', help='逗号分隔，覆盖默认三前端')
    ap.add_argument('--resume', action='store_true')
    ap.add_argument('--db', default=os.path.join(HERE, 'out', 'v4.db'))
    ap.add_argument('--json-dir', default='')
    a = ap.parse_args()

    books = []
    if a.books:
        books += [x.strip() for x in a.books.split(',') if x.strip()]
    if a.books_file:
        books += [x.strip() for x in open(a.books_file, encoding='utf-8') if x.strip()]
    if not books:
        ap.error('需要 --books 或 --books-file')

    raw = json.load(open(RAW_REQ, encoding='utf-8'))
    con = open_db_ext(a.db)
    if a.backend == 'tcp':
        from fq_sign_tcp import TcpSigner
        sig = TcpSigner()
    else:
        from fq_fast import Signer
        sig = Signer()
    print('[*] backend=%s transport=%s books=%d workers=%d rate=%.0f' %
          (a.backend, a.transport, len(books), a.workers, a.rate))

    tag = a.tag_id if a.view == 'long' else None
    col = V4(sig, raw, con, workers=a.workers, rate=a.rate, tag_id=tag,
             sort=a.sort, src=a.view,
             pages=a.pages, transport=a.transport,
             hosts=[h for h in a.hosts.split(',') if h] or None)
    t0 = time.time()
    out, dt = col.run_all(books, resume=a.resume)
    col.report(dt)

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

    try:
        sig.close()
    except Exception:
        pass
    con.close()


if __name__ == '__main__':
    main()