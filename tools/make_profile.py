#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_profile.py —— 从自己设备的提取物生成 profile.json（请求模板）

为什么不直接带 raw_req.json：那里面有 cookie / device_id 等真实设备身份。
所以本仓库只带模板，profile 由你从自己的设备现场生成。

输入（tools/extract_app.ps1 已经拉好的）：
  samples/emulator-com.dragon.read/data/device_state.txt   ← cdid / install_id 摘要
  samples/emulator-com.dragon.read/data/app_data.tar       ← 里面是 shared_prefs（拿 cookie）

输出：
  out/profile.json —— 结构等同于旧版 out/raw_req.json，fq_fast.py 会自动优先用它

用法：
  python tools/make_profile.py
  python tools/make_profile.py --state samples/.../device_state.txt --tar samples/.../app_data.tar
"""
import argparse, io, json, os, re, sys, tarfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, 'out')
DEF_STATE = os.path.join(ROOT, 'samples', 'emulator-com.dragon.read', 'data', 'device_state.txt')
DEF_TAR = os.path.join(ROOT, 'samples', 'emulator-com.dragon.read', 'data', 'app_data.tar')

API_HOST = 'https://api5-normal-sinfonlineb.fqnovel.com'


def read_text(path):
    try:
        return open(path, encoding='utf-8', errors='ignore').read()
    except Exception:
        return ''


def _jserial_ascii(xml, key):
    """cookieStore.xml 里的值是 Java 序列化（ACED + 十六进制）。把该段十六进制解成字节，
    再从中挑出可打印 ASCII 串（cookie 值 / install_id 都是 ASCII）。"""
    i = xml.find('|' + key + '"')
    if i < 0:
        return None
    seg = xml[i:i + 600]
    hexpart = re.sub(r'[^0-9A-Fa-f]', '', seg.split('ACED', 1)[-1]) if 'ACED' in seg else ''
    try:
        raw = bytes.fromhex(hexpart[:len(hexpart) // 2 * 2])
    except Exception:
        return None
    txt = raw.decode('latin1', 'ignore')
    if key in ('install_id', 'iid'):
        m = re.search(r'(?<!\d)(\d{13,16})(?!\d)', txt)
        return m.group(1) if m else None
    m = re.search(r'([0-9a-f]{40,80})', txt)
    return m.group(1) if m else None


def parse_state(txt):
    d = {}
    m = re.search(r'cdid[^A-Za-z0-9]{1,10}([0-9a-f\-]{20,40})', txt)
    if m:
        d['cdid'] = m.group(1)
    iid = _jserial_ascii(txt, 'install_id') or _jserial_ascii(txt, 'iid')
    if iid:
        d['iid'] = iid
    return d


def parse_cookie(tar_path):
    """从 app_data.tar 里的 cookieStore.xml 抠 odin_tt / store-region。"""
    if not os.path.exists(tar_path):
        return ''
    try:
        with tarfile.open(tar_path) as tf:
            for m in tf.getmembers():
                if not m.name.endswith('cookieStore.xml'):
                    continue
                xml = tf.extractfile(m).read().decode('utf-8', 'ignore')
                parts = []
                for key in ('odin_tt', 'store-region', 'store-region-src'):
                    v = _jserial_ascii(xml, key)
                    if v:
                        parts.append('%s=%s' % (key, v))
                if parts:
                    return '; '.join(parts)
    except Exception:
        return ''
    return ''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--state', default=DEF_STATE)
    ap.add_argument('--tar', default=DEF_TAR)
    ap.add_argument('--out', default=os.path.join(OUT, 'profile.json'))
    a = ap.parse_args()

    txt = read_text(a.state)
    if not txt:
        print('[!] 没读到 %s，先用占位值；请先跑 tools/extract_app.ps1' % a.state)
    st = parse_state(txt)
    cdid = st.get('cdid') or '00000000-0000-0000-0000-000000000000'
    iid = st.get('iid') or st.get('iid_alt') or '0'

    cookie = parse_cookie(a.tar) or 'odin_tt=REPLACE_ME'
    if cookie.endswith('REPLACE_ME'):
        print('[!] cookie 没解析出来，手填 out/profile.json 里的 cookie 字段')

    query = ('aid=1967&compliance_status=0'
             '&iid=%s&device_id=%s&ac=wifi&channel=huawei_1967_64'
             '&app_name=novelapp&version_code=71532&version_name=7.1.5.32&device_platform=android'
             '&os=android&ssmix=a&device_type=25102RKBEC&device_brand=REDMI&language=zh&os_api=28'
             '&os_version=9&manifest_version_code=71532&resolution=1080*1920&dpi=480'
             '&update_version_code=71532&_rticket=%%d&&&&host_abi=arm64-v8a&dragon_device_type=pad'
             '&pv_player=71532&need_personal_recommend=1&player_so_load=1&is_android_pad_screen=0'
             '&rom_version=PQ3B.190801.11101518+release-keys'
             '&cdid=%s') % (iid, iid, cdid)

    headers = {
        'accept-encoding': 'gzip',
        'accept': 'application/json; charset=utf-8,application/x-protobuf',
        'content-encoding': 'gzip',
        'x-xs-from-web': '0',
        'x-vc-bdturing-sdk-version': '4.0.3.cn',
        'comment-source': '1',
        'server-channel': '5',
        'lc': '101',
        'sdk-version': '2',
        'passport-sdk-version': '5051451',
        'x-tt-store-region': 'cn-sc',
        'x-tt-store-region-src': 'did',
        'user-agent': ('com.dragon.read/71532 (Linux; U; Android 9; zh_CN; 25102RKBEC; '
                       'Build/PQ3B.190801.11101518;tt-ok/3.12.13.20)'),
        'content-type': 'application/json; charset=utf-8',
        'cookie': cookie,
    }

    prof = {
        'url': API_HOST + '/novel/commentapi/comment/list/7143038691944959011/v1?' + (query % 0),
        'headers': headers,
        '_note': '由 tools/make_profile.py 生成；device_id/iid/cdid/cookie 均来自你自己的设备',
        'device': {'cdid': cdid, 'iid': iid, 'cookie': cookie},
    }
    os.makedirs(OUT, exist_ok=True)
    json.dump(prof, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('[+] 写入 %s' % a.out)
    print('    cdid=%s' % cdid)
    print('    iid=%s' % iid)
    print('    cookie=%s' % (cookie[:60] + ('...' if len(cookie) > 60 else '')))


if __name__ == '__main__':
    main()