#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
soak_v4.py —— v4 稳定性压测（改造 APK 内置签名服务 + 自适应限速）

只关心「长时间跑会不会崩」，统计：
  · 每轮成功 / 失败 / 重试 / 重签
  · 返回码分布（103015 限流 / 110001 签名 / 其它）
  · 签名连接重连次数（App 被杀 / 服务重启的直接指标）
  · App 进程 PID 是否变化（真崩过就会变）
  · 延迟 p50/p95 漂移、限速器当前值

用法：
  python soak_v4.py --rounds 10 --rate 40
  python soak_v4.py --rounds 10 --rate 40 --books 7143038691944959011
"""
import argparse, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fq_fast import RAW_REQ, open_db, MAX_PAGES
from fq_sign_tcp import TcpSigner, ADB, PKG
from fq_fast3 import V4, open_db_ext

BOOKS = ['7143038691944959011', '7276384138653862966', '7361653460183288894']


def pid():
    p = subprocess.run([ADB, 'shell', 'pidof', PKG], capture_output=True, text=True)
    return (p.stdout or '').strip() or None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rounds', type=int, default=10)
    ap.add_argument('--rate', type=float, default=40.0)
    ap.add_argument('--workers', type=int, default=180)
    ap.add_argument('--books', default=','.join(BOOKS))
    ap.add_argument('--db', default=os.path.join(HERE, 'out', 'soak_v4.db'))
    a = ap.parse_args()

    books = [b for b in a.books.split(',') if b]
    raw = json.load(open(RAW_REQ, encoding='utf-8'))
    con = open_db_ext(a.db)
    sig = TcpSigner()
    print('[*] rounds=%d books=%d rate=%.0f app_pid=%s' % (a.rounds, len(books), a.rate, pid()))

    total = {'req': 0, 'ok': 0, 'fail': 0, 'retry': 0, 'resign': 0, 'items': 0}
    marks = []
    t_all = time.time()
    for i in range(a.rounds):
        col = V4(sig, raw, con, workers=a.workers, rate=a.rate, tag_id='-5888420563323975634',
                 pages=MAX_PAGES, transport='urllib', verbose=False)
        t0 = time.time()
        out, dt = col.run_all(books)
        p0 = pid()
        s = col.stat
        total['req'] += s['req']; total['ok'] += s['ok']; total['fail'] += s['fail']
        total['retry'] += s['retry']; total['resign'] += s['resign']; total['items'] += s['items']
        lat = sorted(s['lat'])
        p50 = lat[len(lat) // 2] if lat else 0
        p95 = lat[int(len(lat) * 0.95)] if lat else 0
        marks.append({'round': i + 1, 'req': s['req'], 'ok': s['ok'], 'fail': s['fail'],
                      'retry': s['retry'], 'codes': s['codes'], 'wall': round(dt, 2),
                      'p50': round(p50, 2), 'p95': round(p95, 2),
                      'rate': round(col.rl.rate, 1), 'pid': p0,
                      'signer_reconnects': sig.reconnects})
        print('  R%-2d req=%-4d ok=%-4d fail=%-2d retry=%-2d %5.2fs p50=%.2f p95=%.2f '
              'rl=%.1f pid=%s rec=%d codes=%s' %
              (i + 1, s['req'], s['ok'], s['fail'], s['retry'], dt, p50, p95,
               col.rl.rate, p0, sig.reconnects, s['codes']))

    dt_all = time.time() - t_all
    print('\n===== soak 汇总 =====')
    print('轮数 %d  请求 %d  成功 %d (%.2f%%)  失败 %d  重试 %d  重签 %d' %
          (a.rounds, total['req'], total['ok'],
           100.0 * total['ok'] / max(1, total['req']), total['fail'],
           total['retry'], total['resign']))
    print('条目 %d  总耗时 %.1fs  平均 %.1f req/s  签名重连 %d' %
          (total['items'], dt_all, total['req'] / dt_all, sig.reconnects))
    pids = {m['pid'] for m in marks}
    print('App PID 变化：%s' % ('无（进程未重启）' if len(pids) == 1 else '有 → %s' % pids))
    json.dump(marks, open(os.path.join(HERE, 'out', 'soak_v4.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    sig.close()
    con.close()


if __name__ == '__main__':
    main()