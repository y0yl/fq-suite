# AGENT.md — 交给 agent 的复现手册（评论采集）

> 这份文件写给「下一个接手的人/agent」。按顺序执行，每一步都有**校验点**；校验不过就不要往下走。
> 全部命令在 **pwsh 7** 下执行（Windows PowerShell 5.1 解析 UTF-8 脚本会报 `Unexpected token`）。

---

## 0. 环境检查（30 秒）

```powershell
python -V                      # 3.10+
adb devices                    # 至少一台 device
java -version                  # 17（apktool / javac / apksigner 都靠它）
Test-Path D:\Android\Sdk\build-tools\34.0.0\apksigner.bat
Test-Path D:\RE\tools\apktool\apktool_3.0.3.jar
pip show aiohttp requests
```

`tools\*.ps1` 里写死了三条工具路径，路径不同就改脚本顶部这四行：
`$apktoolJar` / `$jdk` / `$bt`（build-tools）/ `$aj`（android.jar）。

设备要求：**arm64-v8a**（`adb shell getprop ro.product.cpu.abilist` 必须含 arm64-v8a）。
改造包只带 arm64 的 so，x86_64 的 AVD 跑不了（没有 ARM 转译）。

---

## 1. 准备一台设备 + 装官方包

模拟器（雷电 9 / Android 9）或真机、云手机都行。装上 **7.1.5.32** 官方包并**启动到首页**。

> 校验点：`adb shell pm path com.dragon.read` 有输出；`adb shell dumpsys package com.dragon.read | grep versionName` = `7.1.5.32`。

---

## 2. 提取样本（写死版本，后续全靠它）

```powershell
.\tools\extract_app.ps1
```

产出 `samples\emulator-com.dragon.read\`：`base.apk`、10 个关键 so、`data\app_data.tar`（shared_prefs/databases）、
`frida16`、`manifest.json`（逐文件 md5/sha256）、`data\device_state.txt`。

> 校验点：`manifest.json` 里 `lib\arm64\libmetasec_ml.so` 的 md5 = `A2B9619C0761B8A6F74CB346EB86CDDD`。
> 不一致 = 设备上装的不是 71532，后面所有签名行为都可能不同，停。

---

## 3. 生成请求模板

```powershell
python .\tools\make_profile.py
```

从 `device_state.txt` + `app_data.tar` 里解出 `cdid / iid / odin_tt`，写到 `out\profile.json`
（query 串 + 请求头模板）。`fq_fast.py` 会自动优先用 `out\profile.json`。

> 校验点：`out\profile.json` 的 `device.iid` 是 13–16 位十进制、`headers.cookie` 里 `odin_tt` 是 64 位 hex。
> 解析失败就在文件里手填（`cookie` 从 `shared_prefs\cookieStore.xml` 的 `odin_tt` 值取）。

---

## 4. 构建改造 APK

```powershell
.\tools\build_signer_apk.ps1            # 复用已解包目录加 -SkipDecode
```

做的四件事：`apktool d -s`（**不动原 dex**）→ `javac`+`d8` 产出 `classes26.dex` →
往 manifest 注入 `<service>` + 两个 `<receiver>` → `apktool b` + `zipalign` + `apksigner`。

> 校验点：`work\patched_signed.apk` 存在；`apksigner verify --print-certs` 打印你的证书；
> APK 里 `classes26.dex` ≈ 10 KB（`SignServer` + 2 个 receiver）。

**为什么不反编译 smali**：原包含 `libdexvmp.so`（dex 虚拟化 + 自校验），动原 dex 风险高；
追加一个 `classes26.dex` 是侵入最小的做法，实测 71532 不校验自身签名。

---

## 5. 部署到设备

```powershell
.\tools\provision_signer.ps1 -AutoConsent
```

顺序**不能变**：体检 abilist → 卸载/装包 → 灌设备态 tar → 首启 App 并自动点掉隐私弹窗 →
`am start-foreground-service` 起签名服务 → `adb forward tcp:27043` → 跑自检。

> 校验点 A：`adb logcat -d -s DragonSign:*` 有 `listening on 127.0.0.1:27043`
> 校验点 B：`python fq_sign_tcp.py --selftest` 打印 6 个头 + `batch 300 in ~0.5s` + `live request: code=0`
> **只起 service 不首启 App 会 `sign returned null`** —— `NetworkParams` 的回调由 `ms.bd.c.h5.a(long)` 在启动链里注册。

---

## 6. 采集

```powershell
# 大批量（首选）：asyncio + 长连接 + 匀速派发
python fq_fast_aio.py --books-file books.txt --rate 85 --workers 220 --db out\fq.db --json-dir out\json

# 全部评论视图（不走 3000 上限，页数多；sort=1 智能热门 / 3 时间倒序）
python fq_fast_aio.py --books-file books.txt --view all --sort 1 --rate 85 --workers 220 --db out\fq.db

# 小批量（<300 请求）：线程版反而更快（没有冷启动劣势）
python fq_fast3.py --books 7143038691944959011,7276384138653862966 --workers 180 --rate 45

# 断点续跑：只补 pages 表里 ok=0 的页
python fq_fast_aio.py --books-file books.txt --resume --rate 85 --db out\fq.db

# 稳态自测（不改库）
python fq_fast_aio.py --books-file books.txt --rate 85 --workers 220 --bench --rounds 4
```

`books.txt` 一行一个 book_id；没有就先生成：

```powershell
python discover_books.py --validate 20        # 产出 out\books_candidates.txt / books_valid.txt
```

> 校验点：`codes={'0': N}` 全 0；`retry=0 resign=0`；p50 不随轮次漂移。

---

## 7. 排障表（按现象查）

| 现象 | 根因 | 处置 |
|---|---|---|
| `sign returned null` | App 没走完启动链，`tryAddSecurityFactor` 的回调没注册 | 启动 App 到首页（过隐私弹窗），再 `am start-foreground-service` |
| 签名服务连不上 | 进程被杀 / forward 丢失 | `adb shell am broadcast -a com.dragon.sign.START -n com.dragon.read/com.dragon.sign.SignServer$Starter`；重跑 `adb forward` |
| `103001` | 签名头不全（6 个头缺一不可）或 query 被改 | 别裁签名头；query 逐字节保持 |
| `110001` | `x-ss-stub` 与 body 不匹配 / 签名过期 | 每页重签；`stub = MD5(gzip(body)).upper()` 必须进签名输入 |
| `103015` | 速率过高（是限流不是分页上限） | 降 `--rate`；引擎内置退避；多出口 IP |
| 吞吐上不去（<50 req/s） | 用了「每请求新建 TLS」的路径 | 用 `fq_fast_aio.py`（长连接）；不要上 HTTP/2 多路复用（实测更慢） |
| p50 突然变大 | 并发超过服务端拐点 | 并发 ≈ rate × p95；rate 85→220，140→260 |
| 装完起不来 | 设备不是 arm64 | `abilist` 检查；x86_64 AVD 不行 |

---

## 8. 硬性事实（别重新试错）

实测结论，逆版本前都成立：

1. **签名入口**：`NetworkParams.tryAddSecurityFactor(String url, Map<String,List<String>> headers)`；
   底层 `ms.bd.c.k3.a(50331649, 0, ctx, url, headers)`。
2. **不要直接 invoke native 方法**：x86_64 + houdini 转译下会 `art::JNI::GetArrayLength` abort；必须走 Java 层。
3. **6 个签名头缺一不可**（argus/gorgon/khronos/ladon/helios/medusa），少一个 → `103001`。
4. **签名输入 = URL 的 query 串 + `x-ss-stub`**；`user-agent` / `cookie` / 额外头 / **Host** / **URL path** 都可换。
5. 同一签名 **≥300 s** 有效；改 query 任一字节（含 `_rticket`）立即失效。
6. `count` 上限 **50**。**两种视图**：长评（`tag_id` + `server_channel=5`，截断 3000/本 = 60 页）；
   全部（无 tag + `server_channel=9` + `sort=1|3`，实测 40 万+）。两者 `cursor` 都是纯 offset，可预计算 → 全并行。
7. 三个前端域名共用同一签名；但它们只解析到 2 个 IP，**域名轮转不增加容量**，扩容只能换出口 IP。
8. 拐点 **86–90 req/s / 出口 IP**（≈3900–4300 条/s，满页时）。

---

## 9. 验收清单（交付前自查）

```
[ ] python fq_sign_tcp.py --selftest         → 6 头 + code=0
[ ] python fq_fast_aio.py --bench --rounds 4 → 0 失败、抖动 < 0.5
[ ] 3 本书入库条数与页面 total 对得上（去重后 2900+）
[ ] adb logcat 无 DragonSign 报错；App PID 未变
[ ] out\profile.json / samples\ 未提交到仓库（.gitignore 已挡）
```