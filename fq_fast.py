#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fq_fast.py —— 番茄小说长评高速采集器（借签名架构 v2）

架构（与旧方案 v1 的区别）：
  v1: Python --RPC--> App.post() --HTTP--> 服务端     每请求一次 RPC，78-85 条/s
  v2: App 只负责「签名」（NetworkParams.tryAddSecurityFactor），
      HTTP 全部由 Python 并发直发，签名批量预取             1000+ 条/s

关键事实（本目录 exp_matrix.py / bench3.py / bench4.py 实测）：
  1. 签名入口 = com.bytedance.frameworks.baselib.network.http.NetworkParams
                .tryAddSecurityFactor(String url, Map<String,List<String>> headers)
     纯 Java 静态方法，内部走 k3.a(50331649, 0, ctx, url, headers) → libmetasec_ml.so
  2. 签名绑定 headers，其中 x-ss-stub 必须在签名输入里（= MD5(gzip(body)).upper()）
  3. 签名不吃 body 本体，但吃 x-ss-stub ⇒ 每页必须单独签名
  4. 同一签名可重复使用（同 body 重试无需重签），时间窗 > 20s
  5. 直调 y2.a（native）在 x86_64 + houdini 会 abort，必须走 Java 层

用法：
  python fq_fast.py --books 7143038691944959011,7276384138653862966
  python fq_fast.py --books-file books.txt --workers 180 --db out/fast.db
"""
import argparse, gzip, hashlib, json, os, re, sqlite3, ssl, sys, threading, time
import urllib.request, urllib.error, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import frida

# ---------------------------------------------------------------- constants
DEV_ADDR = '127.0.0.1:27042'
PKG = 'com.dragon.read'
_ADB_LOCAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'platform-tools', 'adb.exe')
ADB = os.environ.get('ADB') or (_ADB_LOCAL if os.path.exists(_ADB_LOCAL) else 'adb')
HERE = os.path.dirname(os.path.abspath(__file__))
_raw = os.path.join(HERE, 'out', 'raw_req.json')
_prof = os.path.join(HERE, 'out', 'profile.json')
RAW_REQ = _raw if os.path.exists(_raw) else _prof

SIGKEYS = ('x-argus', 'x-gorgon', 'x-helios', 'x-khronos', 'x-ladon', 'x-medusa')
API_HOST = 'https://api5-normal-sinfonlineb.fqnovel.com'
API_PATH = '/novel/commentapi/comment/list/%s/v1'
_DEFAULT_QUERY = ('aid=1967&compliance_status=0&iid=0&device_id=0&ac=wifi&channel=huawei_1967_64'
                  '&app_name=novelapp&version_code=71532&version_name=7.1.5.32&device_platform=android'
                  '&os=android&ssmix=a&device_type=25102RKBEC&device_brand=REDMI&language=zh&os_api=28'
                  '&os_version=9&manifest_version_code=71532&resolution=1080*1920&dpi=480'
                  '&update_version_code=71532&_rticket=%d&&&&host_abi=arm64-v8a&dragon_device_type=pad'
                  '&pv_player=71532&need_personal_recommend=1&player_so_load=1&is_android_pad_screen=0'
                  '&rom_version=PQ3B.190801.11101518+release-keys&cdid=0')


def _query_from_profile():
    """query 串（iid/device_id/cdid/klink_egdi 等设备参数）从 out/profile.json 取；
    没有 profile 就退回占位模板（那种情况服务端会拒，属预期）。"""
    try:
        p = json.load(open(RAW_REQ, encoding='utf-8'))
        q = p['url'].split('?', 1)[1]
        return re.sub(r'_rticket=\d+', '_rticket=%d', q)
    except Exception:
        return _DEFAULT_QUERY


QUERY = _query_from_profile()

PAGE = 50
MAX_PAGES = 60  # 服务端长评上限 3000 / 50

JS_AGENT = r"""
Java.perform(function () {
  var NP = Java.use('com.bytedance.frameworks.baselib.network.http.NetworkParams');
  var HM = Java.use('java.util.HashMap');
  var AL = Java.use('java.util.ArrayList');

  function map2obj(m) {
    if (m === null) return null;
    var o = {}, keys = m.keySet().toArray();
    for (var i = 0; i < keys.length; i++) o[String(keys[i])] = String(m.get(keys[i]));
    return o;
  }
  function build(h) {
    var m = HM.$new();
    for (var k in h) { var l = AL.$new(); l.add(String(h[k])); m.put(k, l); }
    return m;
  }
  rpc.exports = {
    ping: function () { return 1; },
    signMany: function (url, hjList) {
      var out = [];
      for (var i = 0; i < hjList.length; i++) {
        out.push(map2obj(NP.tryAddSecurityFactor(url, build(JSON.parse(hjList[i])))));
      }
      return { ok: true, h: out };
    }
  };
  send('ready');
});
"""

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------- signer
class Signer:
    """Frida 侧签名机：批量产出 6 个签名头。"""

    def __init__(self, addr=DEV_ADDR, pkg=PKG):
        self.addr, self.pkg = addr, pkg
        self.sess = None
        self.sc = None
        self._lock = threading.Lock()
        self.attach()

    def _pid(self):
        p = subprocess.run([ADB, 'shell', 'pidof', self.pkg], capture_output=True, text=True)
        o = (p.stdout or '').strip()
        return int(o.split()[0]) if p.returncode == 0 and o else None

    def attach(self):
        pid = self._pid()
        if not pid:
            subprocess.run([ADB, 'shell', 'monkey', '-p', self.pkg,
                            '-c', 'android.intent.category.LAUNCHER', '1'], capture_output=True)
            for _ in range(30):
                time.sleep(1)
                pid = self._pid()
                if pid:
                    break
        if not pid:
            raise RuntimeError('App 未运行且拉起失败')
        dev = frida.get_device_manager().add_remote_device(self.addr)
        self.sess = dev.attach(pid)
        self.sc = self.sess.create_script(JS_AGENT)
        self.sc.on('message', lambda m, d: None)
        self.sc.load()
        for _ in range(50):
            try:
                if self.sc.exports_sync.ping() == 1:
                    return True
            except Exception:
                pass
            time.sleep(0.1)
        raise RuntimeError('签名 agent 未就绪')

    def sign_many(self, url, header_list):
        """header_list: List[dict] -> List[dict]（6 个签名头）"""
        with self._lock:
            try:
                r = self.sc.exports_sync.sign_many(
                    url, [json.dumps(h, ensure_ascii=False) for h in header_list])
            except Exception:
                # App 挂了 / script 失效 → 重建一次
                try:
                    self.sess.detach()
                except Exception:
                    pass
                self.attach()
                r = self.sc.exports_sync.sign_many(
                    url, [json.dumps(h, ensure_ascii=False) for h in header_list])
        if not r or not r.get('ok'):
            raise RuntimeError('sign failed: %s' % (r,))
        return r['h']

    def close(self):
        try:
            self.sess.detach()
        except Exception:
            pass


# ---------------------------------------------------------------- http
def http_post(url, headers, body, timeout=60):
    """
    返回 dict(code, n, items, cursor, total, dt, err)
    请求体自动 gzip，x-ss-stub 由签名阶段绑定，这里只发。
    """
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            raw = r.read()
            ce = (r.headers.get('content-encoding') or '').lower()
    except urllib.error.HTTPError as e:
        raw, ce = e.read(), ''
    except Exception as e:
        return {'code': 'EXC', 'n': 0, 'items': [], 'dt': time.time() - t0, 'err': repr(e)}
    dt = time.time() - t0
    if 'gzip' in ce or raw[:2] == b'\x1f\x8b':
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
            'total': ci.get('total'), 'dt': dt,
            'extra': d.get('extra') or {}}


# ---------------------------------------------------------------- payload
def make_body(book, cursor=None, count=PAGE, tag_id=None, sort=1):
    bp = {"book_id": book, "comment_sort_debug": False, "end_offset_time": 0,
          "item_count": 0, "max_item_count": 0, "need_count": True,
          "need_danmaku_occlusion_face_data": False, "para_index": 0,
          "read_item_count": 0, "req_type": 0, "start_offset_time": 0,
          "playlet_item_duration": 0}
    b = {"business_param": bp, "comment_source": 1, "comment_type": 2, "count": count,
         "group_id": book, "group_type": 1, "server_channel": 9}
    if tag_id:
        # 长评视图：server_channel=5 + tag_id，服务端截断 3000/本
        bp["tag_id"] = tag_id
        bp["fold_type"] = 0
        b["server_channel"] = 5
    else:
        # 全部视图：server_channel=9 + sort（1=智能热门 / 3=时间倒序），实测可达 40 万+
        b["server_channel"] = 9
        b["sort"] = sort
    if cursor is not None:
        b["cursor"] = str(cursor)
    return json.dumps(b, separators=(',', ':')).encode()


def api_url(book, nm):
    return (API_HOST + (API_PATH % book) + '?' + (QUERY % nm))


def base_headers(raw, nm):
    h = {k: v for k, v in raw['headers'].items()
         if k.lower() not in SIGKEYS and k.lower() not in ('content-length', 'x-ss-stub')}
    h['x-ss-req-ticket'] = str(nm)
    h['x-reading-request'] = '%d-%d' % (nm, 773423536)
    return h


# ---------------------------------------------------------------- db
SCHEMA = """
CREATE TABLE IF NOT EXISTS comments(
  id TEXT NOT NULL, src TEXT NOT NULL DEFAULT 'long', book TEXT,
  uid TEXT, uname TEXT, ts INT, txt TEXT, raw TEXT,
  PRIMARY KEY (id, src));
CREATE INDEX IF NOT EXISTS idx_book ON comments(book, src);
CREATE TABLE IF NOT EXISTS books(
  book TEXT PRIMARY KEY, total INT, fetched INT, status TEXT, updated_at INT);
CREATE TABLE IF NOT EXISTS meta(
  book TEXT PRIMARY KEY, book_name TEXT, author TEXT, score TEXT,
  tag_id TEXT, tag_name TEXT, total_in_app INT, collected_at INT);
"""


def open_db(path):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=NORMAL')
    con.executescript(SCHEMA)
    cols = [r[1] for r in con.execute('PRAGMA table_info(comments)')]
    if cols and 'src' not in cols:                 # 老库迁移
        con.execute("ALTER TABLE comments ADD COLUMN src TEXT NOT NULL DEFAULT 'long'")
    con.commit()
    return con


def record_of(item, book):
    c = item.get('comment') or item
    cm = c.get('common') or {}
    ui = cm.get('user_info') or {}
    bi = ui.get('base_info') or {}
    tag = ui.get('user_tag') or {}
    ex = c.get('expand') or {}
    stat = c.get('stat') or {}
    txt = ((cm.get('content') or {}).get('text') or '')
    return {
        'id': c.get('comment_id'),
        'src': SRC,
        'book': book,
        'uid': bi.get('user_id'),
        'uname': bi.get('user_name'),
        'ts': cm.get('create_timestamp'),
        'txt': txt,
        'is_author': tag.get('is_author'),
        'score': ex.get('score'),
        'digg': stat.get('digg_count'),
        'reply': stat.get('reply_count'),
        'show_pv': stat.get('show_pv'),
        'read_s': stat.get('read_duration'),
        'listen_s': stat.get('listen_duration'),
        'raw': json.dumps(item, ensure_ascii=False, separators=(',', ':')),
    }


# ---------------------------------------------------------------- collector
class Collector:
    def __init__(self, signer, raw, con, workers=180, tag_id=None, verbose=True):
        self.sig = signer
        self.raw = raw
        self.con = con
        self.workers = workers
        self.tag_id = tag_id
        self.verbose = verbose
        self.stat = {'req': 0, 'ok': 0, 'items': 0, 'fail': 0}
        self._db_lock = threading.Lock()

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    def _prep_batch(self, book, cursors):
        """构造 + 批量签名。返回 (url, [(headers, gzbody)], cursor_list)"""
        nm = int(time.time() * 1000)
        url = api_url(book, nm)
        bh = base_headers(self.raw, nm)
        hjs, finals, bodies = [], [], []
        for cur in cursors:
            body = make_body(book, cur, PAGE, self.tag_id)
            gz = gzip.compress(body)
            si = dict(bh)
            si['x-ss-stub'] = hashlib.md5(gz).hexdigest().upper()
            hjs.append(si)
            f = dict(si)
            f['content-length'] = str(len(gz))
            finals.append(f)
            bodies.append(gz)
        sigs = self.sig.sign_many(url, hjs)
        for f, s in zip(finals, sigs):
            f.update(s)
        return url, list(zip(finals, bodies)), cursors

    def _save(self, book, res_items):
        rows = []
        for it in res_items:
            r = record_of(it, book)
            if not r['id']:
                continue
            rows.append((r['id'], r['book'], r['uid'], r['uname'], r['ts'], r['txt'], r['raw']))
        if not rows:
            return 0
        with self._db_lock:
            cur = self.con.executemany(
                'INSERT OR IGNORE INTO comments(id,book,uid,uname,ts,txt,raw) VALUES (?,?,?,?,?,?,?)',
                rows)
            self.con.commit()
            return cur.rowcount if cur.rowcount >= 0 else len(rows)

    def probe(self, book):
        """第一页：拿 total / tag_id / 书籍元信息"""
        url, pairs, _ = self._prep_batch(book, [None])
        h, gz = pairs[0]
        r = http_post(url, h, gz)
        if r.get('code') != 0:
            self.log('  [!] %s probe code=%s %s' % (book, r.get('code'), r.get('err', '')))
            return None
        self._save(book, r['items'])
        ex = r.get('extra') or {}
        bi = ex.get('book_info') or {}
        self.meta = {
            'book': book, 'book_name': bi.get('book_name'), 'author': bi.get('author'),
            'score': bi.get('score'), 'tag_id': self.tag_id,
            'tag_name': '长评' if self.tag_id else None,
            'total_in_app': r.get('total'), 'collected_at': int(time.time()),
        }
        self.log('  [%s] total=%s book=%s author=%s' %
                 (book, r.get('total'), bi.get('book_name'), bi.get('author')))
        return r

    def run_book(self, book):
        t0 = time.time()
        first = self.probe(book)
        if not first:
            return {'book': book, 'status': 'probe_fail', 'items': 0}
        total = first.get('total') or 3000
        pages = min(MAX_PAGES, max(1, (total + PAGE - 1) // PAGE))
        cursors = [PAGE * i for i in range(1, pages)]

        url, pairs, _ = self._prep_batch(book, cursors)
        self.stat['req'] += len(pairs)

        items_total = first['n']
        fails = 0
        with ThreadPoolExecutor(max_workers=min(self.workers, max(1, len(pairs)))) as ex:
            futs = [ex.submit(http_post, url, h, gz) for h, gz in pairs]
            for f in as_completed(futs):
                r = f.result()
                if r.get('code') != 0:
                    fails += 1
                    self.stat['fail'] += 1
                    continue
                self.stat['ok'] += 1
                items_total += r['n']
                self._save(book, r['items'])

        dt = time.time() - t0
        n_db = list(self.con.execute('select count(*) from comments where book=?', (book,)))[0][0]
        self.con.execute('INSERT OR REPLACE INTO books(book,total,fetched,status,updated_at) '
                         'VALUES (?,?,?,?,?)', (book, total, n_db, 'done', int(time.time())))
        m = dict(self.meta) if hasattr(self, 'meta') else {}
        m.update({'book': book, 'total_in_app': total})
        self.con.execute('INSERT OR REPLACE INTO meta(book,book_name,author,score,tag_id,'
                         'tag_name,total_in_app,collected_at) VALUES (?,?,?,?,?,?,?,?)',
                         (m.get('book'), m.get('book_name'), m.get('author'), m.get('score'),
                          m.get('tag_id'), m.get('tag_name'), m.get('total_in_app'),
                          int(time.time())))
        self.con.commit()
        self.stat['items'] += items_total
        self.log('  [done] %s  %d 页  %d 条(去重后)  %.2fs  fails=%d' %
                 (book, len(pairs) + 1, n_db, dt, fails))
        return {'book': book, 'status': 'done', 'pages': len(pairs) + 1,
                'items': n_db, 'sec': round(dt, 2), 'fails': fails}


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--books', help='逗号分隔 book_id')
    ap.add_argument('--books-file', help='每行一个 book_id')
    ap.add_argument('--tag-id', default='-5888420563323975634', help='长评标签，默认全局长评')
    ap.add_argument('--workers', type=int, default=180)
    ap.add_argument('--db', default=os.path.join(HERE, 'out', 'fast.db'))
    ap.add_argument('--json-dir', default=os.path.join(HERE, 'out', 'fast_json'))
    ap.add_argument('--raw', default=RAW_REQ)
    args = ap.parse_args()

    books = []
    if args.books:
        books += [b.strip() for b in args.books.split(',') if b.strip()]
    if args.books_file:
        books += [l.strip() for l in open(args.books_file, encoding='utf-8') if l.strip()]
    if not books:
        ap.error('需要 --books 或 --books-file')

    raw = json.load(open(args.raw, encoding='utf-8'))
    con = open_db(args.db)
    print('[*] books=%d workers=%d db=%s' % (len(books), args.workers, args.db))

    t_all = time.time()
    sig = Signer()
    print('[*] signer ready')
    col = Collector(sig, raw, con, workers=args.workers, tag_id=args.tag_id)
    results = []
    for b in books:
        print('\n=== %s ===' % b)
        results.append(col.run_book(b))
    dt = time.time() - t_all
    sig.close()

    tot_items = col.stat['items']
    print('\n===== 汇总 =====')
    print('书: %d   请求: %d (ok=%d fail=%d)   条目: %d   耗时: %.2fs' %
          (len(books), col.stat['req'], col.stat['ok'], col.stat['fail'], tot_items, dt))
    print('吞吐: %.1f 条/s   %.1f 请求/s   平均 %.2fs/本' %
          (tot_items / dt, col.stat['req'] / dt, dt / max(1, len(books))))

    if args.json_dir:
        os.makedirs(args.json_dir, exist_ok=True)
        for r in results:
            if r['status'] != 'done':
                continue
            b = r['book']
            rows = list(con.execute('select raw from comments where book=?', (b,)))
            m = list(con.execute('select * from meta where book=?', (b,)))
            out = []
            for (rj,) in rows:
                try:
                    it = json.loads(rj)
                except Exception:
                    continue
                rec = record_of(it, b)
                rec.pop('raw', None)
                out.append(rec)
            meta = {}
            if m:
                meta = {'book_name': m[0][1], 'author': m[0][2], 'score': m[0][3],
                        'tag_id': m[0][4], 'tag_name': m[0][5], 'total_in_app': m[0][6]}
            p = os.path.join(args.json_dir, '%s.json' % b)
            json.dump({'book': b, 'meta': meta, 'count': len(out), 'reviews': out},
                      open(p, 'w', encoding='utf-8'), ensure_ascii=False)
            print('[json] %s  %d 条' % (p, len(out)))
    con.close()


if __name__ == '__main__':
    main()