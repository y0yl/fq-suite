# fq-suite — 番茄小说评论采集工具链

把「签名」从 App 运行时里拆出来，变成一台设备上的本地端口；采集侧用 asyncio 长连接跑满吞吐。

支持两种视图：**全部评论**（实测 40 万+/本）与 **长评**（服务端截断 3000/本）。

```
┌──────────── 一台 Android 设备（真机 / 云手机 / 模拟器都行）────────────┐
│  改造版 com.dragon.read                                               │
│    com.dragon.sign.SignServer  →  NetworkParams.tryAddSecurityFactor  │
│    监听 127.0.0.1:27043，行分隔 JSON，535–600 签/s                     │
└──────────────────────────▲────────────────────────────────────────────┘
                           │ adb forward tcp:27043
┌──────────────────────────┴────────────────────────────────────────────┐
│  主机 Python                                                          │
│    fq_sign_tcp.py    签名客户端（连接池 6 / 断线重连 / 自动拉起 App）    │
│    fq_fast_aio.py    采集引擎（asyncio + 长连接 + 匀速派发）            │
│    fq_fast3.py       线程版引擎（小批量更快）                           │
│    discover_books.py 书单发现（web 站零签名）                           │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 一、两种视图

| 视图 | 参数 | body 关键字段 | 服务端上限 | 说明 |
|---|---|---|---|---|
| **长评** | `--view long`（默认） | `business_param.tag_id` + `server_channel=5` | 截断 **3000/本** = 60 页 | 单页 50 条基本填满，快 |
| **全部评论** | `--view all --sort 1\|3` | 无 tag + `server_channel=9` | 实测 **40 万+** | `sort=1` 智能热门、`sort=3` 时间倒序；`sort=2` 返回 `103001`，不要用 |

两个视图的 `cursor` 都是**纯 offset**，可预计算后全并行。落库用 `(id, src)` 做主键、
`pages` 用 `(book, src, cursor)`，同一评论在两个视图都出现时不会互相覆盖。

---

## 二、实测

单台设备、单出口 IP、13 本真实书单（3 本热书 + 10 本发现书）× 30 页：

| 场景 | 请求 | 墙钟 | req/s | 条目/s | 失败 | 抖动 |
|---|---|---|---|---|---|---|
| 单轮 | 390 | 6.82 s | 57.2 | 1196 | 0 | — |
| **稳态 4 轮** | **1560** | **19.7 s** | **79.1** | 1656 | **0** | **0.26** |
| 热书（每页满 50 条） | 1800 | 23.9 s | 75–86 | **3900–4300** | 0 | 0.26 |

条目吞吐 = 请求吞吐 × 每页 50 × 书目命中率。上表第二行的 1656 条/s 是因为 13 本里有 6 本冷门
（长评 2–29 条、大量空页）；全热书时就是 3900–4300 条/s。

签名侧：内置服务 **535–600 签/s**（批量 300 约 0.5 s），比 frida RPC 的 450 签/s 更快，余量 10 倍以上。

---

## 三、快速开始

```powershell
# 0) 依赖：Python 3.10+ / aiohttp requests / JDK17 / Android SDK build-tools 34 / apktool 3.0.3 / adb
pip install aiohttp requests

# 1) 从设备提取样本（APK / 关键 so / 私有数据 / 设备态）
.\tools\extract_app.ps1

# 2) 生成请求模板（设备身份 + cookie 都来自你自己的设备，不进仓库）
python .\tools\make_profile.py

# 3) 构建改造 APK（内置签名服务）
.\tools\build_signer_apk.ps1

# 4) 部署到设备（体检 → 装包 → 灌设备态 → 过隐私 → 起服务 → 自检）
.\tools\provision_signer.ps1 -AutoConsent

# 5) 自检：应看到 500+ 签/s 且一条真实请求 code=0
python fq_sign_tcp.py --selftest

# 6) 采集
python fq_fast_aio.py --books-file books.txt --view long --rate 85 --workers 220 --db out\fq.db
python fq_fast_aio.py --books-file books.txt --view all --sort 1 --rate 85 --workers 220 --db out\fq.db
```

没有书单就先发现：

```powershell
python discover_books.py --validate 20     # 产出 out\books_candidates.txt / books_valid.txt
```

---

## 四、目录

| 路径 | 作用 |
|---|---|
| `fq_fast.py` | 核心库：请求模板、body 构造、gzip+stub、落库 schema、frida 版 Signer |
| `fq_sign_tcp.py` | 签名客户端（连改造 APK 的 27043），接口与 `fq_fast.Signer` 一致 |
| `fq_fast_aio.py` | **主力引擎**：asyncio + aiohttp 长连接 + 匀速派发 + 页级续跑 + 六 Host 轮转 |
| `fq_fast3.py` | 线程版引擎（<300 请求更快），AIMD 限速 + 失败分型 |
| `discover_books.py` | 书单发现：web 站抽 book_id（零签名）+ commentapi 校验 |
| `bench_steady.py` | 三引擎稳态基准（threads / session / aiohttp，输出抖动） |
| `probe_sigset.py` / `probe_bind.py` / `probe_hosts.py` | 签名面实验：哪些头必需、哪些字段可变、哪些域名可用 |
| `soak_v4.py` | 稳定性压测（统计 App PID 漂移与签名重连） |
| `tools\build_signer_apk.ps1` | 一键构建改造 APK（apktool -s → javac → d8 → manifest 注入 → apksigner） |
| `tools\extract_app.ps1` | 一键提取 APK / 关键 so / 私有数据 / frida16 + manifest 哈希 |
| `tools\provision_signer.ps1` | 任意 adb 设备一键部署 |
| `tools\make_profile.py` | 从提取物生成 `out\profile.json`（设备 query + cookie 模板） |
| `apkpatch\src\...\SignServer.java` | 内置签名服务源码（TCP 服务 + 反射调 `tryAddSecurityFactor`） |
| `AGENT.md` | 给 agent 的逐步复现手册（校验点 + 排障表 + 硬性事实 + 验收清单） |

---

# 五、技术分析

## 5.1 问题定义

番茄 App 的评论接口要求 6 个动态签名头，缺一个就 `103001`。签名的输入由 App 运行时决定，
想批量抓就必须解决「谁来签名」。三条路：

| 路线 | 结论 |
|---|---|
| 纯算法复刻（自己算 6 个头） | 密码学原语是标准的，但拼装逻辑被 OLLVM 控制流扁平化包住，且设备指纹不可离线 → 不做 |
| 让 App 只当签名机（进程内调用） | 可行，但注入方式决定稳定性 |
| **把签名调用编译进 App 自己** | ✅ 本实现 |

核心判断：**签名不是要复刻的算法，是要稳定调用的一个函数。** 把它从「外部注入」变成「App 自带」，
就把整个不稳定源（注入框架、会话失效、转译层 native 调用）从链路上剪掉了。

## 5.2 签名机制：实测出来的边界

入口是纯 Java 静态方法，内部转 native：

```
NetworkParams.tryAddSecurityFactor(url, Map<String,List<String>> headers)
  → ms.bd.c.k3.a(50331649, 0, ctx, url, String[] flattenedHeaders)   // native → libmetasec_ml.so
  → 返回 Map：x-argus / x-gorgon / x-khronos / x-ladon / x-helios / x-medusa
```

20 多组受控实验（`probe_sigset.py` / `probe_bind.py`）的结论，直接决定了架构：

| 事实 | 证据 | 对设计的影响 |
|---|---|---|
| **6 个头缺一不可** | 少任何一个 → `103001` | 没有「只算便宜的 gorgon」的捷径 |
| **签名输入 = URL 的 query 串 + `x-ss-stub`** | 只给 `x-ss-stub` 也过；把业务头全去掉也过 | 请求头可自由随机化 |
| `x-ss-stub = MD5(gzip(body)).upper()` | 抓包字节逐字节核对 | 换 body 必须重签，一页一签 |
| UA / Cookie / 额外头 **不参与** | 改 UA、改 cookie、加 `x-foo` → 仍 `code=0` | 可换 IP、可换指纹 |
| **Host 不参与** | `sinfonlineb` → `sinfonlinec` / `lf` 都过 | 多前端分流（但不增容量，见 5.7） |
| **URL path 不参与** | 换 book id 仍过 | 同一套能力可服务任意接口 |
| query **逐字节**绑定 | 改 `_rticket`、加 `foo=1`、删 `klink_egdi` → 全挂 | query 由 profile 统一生成，运行期不可变 |
| 时间窗 **≥300 s** | +30/90/300 s 重放全部 `code=0` | 可批量预签，签名机与采集机解耦 |
| `count` 上限 **50** | 传 100/200/500 都只回 50 | 3000 条上限 = 60 页/本 |
| tag 模式 `cursor` = **纯 offset 字符串** | 返回 `"50"`/`"100"` | 60 页可一次性全并行，不需要顺序翻页 |

## 5.3 为什么改 APK，以及怎么改

### 旧方式的三个不稳定源

进程内调用（frida attach 后 RPC 调 `tryAddSecurityFactor`）实测三个坑：

1. **会话失效**：script 掉线后必须重建，长跑时是主要失败点；
2. **转译层**：x86_64 模拟器上 App 是 arm64 + houdini 转译，从 JS 线程直接 invoke native 方法会 `art::JNI::GetArrayLength` abort；
3. **注入痕迹**：frida-server 常驻 + agent 线程，属于额外的可观测面。

把调用**编译进 APK**，三个问题同时消失：没有会话、调用路径与 App 自身网络栈完全一致、没有外部组件。

### 注入方式：只追加，不改原 dex

```
base.apk
 ├─ classes.dex … classes25.dex   ← 一个字节不动（避开 libdexvmp 的 dex 虚拟化与自校验）
 ├─ classes26.dex                 ← 新增 ~10 KB：com.dragon.sign.SignServer + 2 个 receiver
 └─ AndroidManifest.xml           ← 只加 1 个 <service> + 2 个 <receiver>
```

用 `apktool d -s` 保留原始 dex，只解资源与 manifest；新 dex 用 `javac --release 8` + `d8` 生成；
重打包后 `zipalign` + `apksigner` 自签。实测 71532 **不校验自身签名**：自签包正常启动、
隐私弹窗后进首页、签名调用正常。

### 一个必须记住的时序

`tryAddSecurityFactor` 内部检查 `NetworkParams.sAddSecurityFactorProcessCallback`，
该回调由 `ms.bd.c.h5.a(long)` 在 **App 启动链**里注册。所以顺序固定：

> 装包 → 灌设备态 → **启动 App 到首页**（过隐私弹窗）→ 起 service

只起 service 不首启，会得到 `sign returned null`。这不是 bug，是初始化顺序。

### 服务协议

行分隔 JSON（`127.0.0.1:27043`），一次可批量：

```
→ {"url":"<url>","batch":[{"x-ss-stub":"…"},…]}
← {"ok":true,"h":[{X-Argus,X-Gorgon,X-Khronos,X-Ladon,X-Helios,X-Medusa},…],"n":300}
→ {"ping":1}
← {"ok":true,"pong":1,"ver":"7.1.5.32"}
```

## 5.4 引擎：为什么是 asyncio 长连接 + 匀速派发

### 先把「服务端饱和 50 req/s」证伪

旧实现用线程池 + `urllib`，每请求重建 TLS，43 req/s 就上不去，一度被误判为服务端限速。拆开看：

| 引擎（同一批 1800 请求） | req/s | p50 | 每秒完成数抖动 |
|---|---|---|---|
| 线程池 + urllib（每请求 TLS） | 54.1 | 3.81 s | 0.74 |
| **asyncio + aiohttp 长连接 + 匀速 85/s（并发 220）** | **75.3** | **1.05 s** | **0.26** |
| 同引擎 匀速 140/s（并发 260） | 85.8 | 2.06 s | 0.46 |
| 同引擎 匀速 220/s（并发 320） | 79.0 | 3.12 s | 0.36 |

**43 req/s 是客户端天花板，不是服务端的。** 换成长连接后 85 req/s 连打 3600 个请求，
服务端一次 `103015` 都没给。

### 三个具体改动

1. **长连接**：720 个请求只开 ~20 条 TLS。握手是 CPU 活，GIL 下串行，是旧实现最大的隐性成本；
   顺带把「服务端看到的新建连接速率」降了 30 倍。
2. **匀速派发**（每个请求占一个 `1/rate` 时间槽）替代令牌桶：令牌桶允许「攒满就突发」，
   突发直接抬高 p99 并触发限流；匀速把请求铺成等间隔，完成速率曲线接近直线。
3. **签名丢线程池**：签名是同步 TCP（~2 ms），在协程里直接调会阻塞事件循环，600 次就是 1.2 s 卡顿，
   直接变成抖动。

### 并发怎么配

并发必须 ≥ `rate × p95`，否则队列堆积、实际速率达不到目标：

- 稳档：`--rate 85 --workers 220` → 75 req/s、抖动 0.26；
- 快档：`--rate 140 --workers 260` → 86 req/s、抖动 0.46、p50 2 s；
- 再往上（220/320）p50 反弹、吞吐反降 —— 拐点在 **86–90 req/s**。

### 不要做的事（都实测过）

- **不要上 HTTP/2 多路复用**：服务端支持 h2，但单连接多路复用在这条链路上更慢（25 req/s）；
- **不要用 `requests.Session` 做 keep-alive**：线程池每线程只发一个请求，建 Session 的开销反噬（28.7 req/s）；
- **小批量不要用 asyncio**：<300 请求时冷启动 TLS 占比太高，线程版 4.16 s 比 asyncio 的 5.91 s 快。

## 5.5 失败分型与自愈

| 返回 | 含义 | 处置 |
|---|---|---|
| `0` | 正常 | 记账，限速器缓慢提速 |
| `103001` | 签名头不全 / query 被改 / `sort=2` | 不重试，直接报错（配置错误） |
| `110001` | `x-ss-stub` 与 body 不符 / 签名过期 | **重签**再发 |
| `103015` | 限流 | 退避 + 降速（AIMD ×0.6） |
| `EXC` / `BADJSON` | 连接坏 / 非 JSON | 换连接 + 重签 |
| 页级失败 | 重试 3 轮仍失败 | 写 `pages` 表 `ok=0`，`--resume` 只补这些页 |

稳定性实测：1800 请求 **100% 成功、0 重试 0 重签、App 进程 PID 未变、签名连接 0 重连**。

## 5.6 书单发现

`discover_books.py` 三个来源，按成本排序：

| 来源 | 可用性 | 说明 |
|---|---|---|
| **番茄 web 站**（`fanqienovel.com/rank`、`/library`） | ✅ 立即用 | HTML 里带 `/page/<book_id>`，**零签名** |
| App 的 `bookmall/tab`、`new_category/front`、`bookmall/cell/change` | 接口已定位（dex 里的真实 path） | 要逆 POST body 模型，下一阶段 |
| 评论响应的 `extra.book_info` | ❌ | 只回当前书，扩散不了 |

实测一轮拿到 20 个候选，commentapi 校验后 **10 个有长评**（命中率 50%）。

## 5.7 边界与已知限制

| 限制 | 数值/现状 | 说明 |
|---|---|---|
| 长评上限 | 3000 条/本（60 页 × 50） | 服务端截断，非采集限制；全部视图无此限制 |
| 单 IP 上限 | 86–90 req/s | 再上只能换出口 IP；6 个前端域名只解析到 2 个 IP，域名轮转无效 |
| 版本绑定 | 7.1.5.32 / `libmetasec_ml.so` md5 `A2B9619C…` | 换版本要重建 APK + 重跑签名面回归 |
| 设备依赖 | 一台 arm64 Android（真机/云手机/模拟器） | 纯 PC 化未完成（见下） |
| 自动更新 | 必须关闭 | 商店回滚成官方包，签名服务就没了 |

**为什么不上纯 PC（unidbg）**：JNI 环境、签名入口、ctx 内存回放都已打通，但 `init` 依赖 App 的
Java 初始化序列（`MSConfig` / `MSManager`，重度依赖 Android Context），补这一层要 2–3 人日，
收益只是「省掉一台设备」——而现在一台设备就能覆盖 4000 条/s。所以那条线留在研究侧，不进生产。

## 5.8 设计取舍一览

| 决策 | 备选 | 为什么选它 |
|---|---|---|
| 改 APK 内置签名 | frida 注入 / 纯算法 | 去掉会话与转译层两个不稳定源，改动面最小（一个 10 KB dex） |
| 追加 dex 不动原 dex | 反编译 smali 全量改 | 避开 dex VMP 与自校验，重打包风险最低 |
| asyncio + 长连接 | 线程池 + urllib | 同一批请求 54 → 79 req/s，p50 3.8 → 0.8 s，抖动 0.74 → 0.26 |
| 匀速派发 | 令牌桶 / 无限并发 | 抖动最小；无限并发会让 p50 反弹、吞吐反降 |
| 页级 `pages` 表 + `--resume` | 整本重跑 | 失败页只补一次，长跑不用从头再来 |
| 书单发现走 web 站 | 逆 App 的 bookmall 接口 | web 站 HTML 直接带 `book_id`，**零签名**、零成本 |

---

## 六、目标版本与合规

`com.dragon.read` **7.1.5.32 / versionCode 71532**，`libmetasec_ml.so` arm64 md5 `A2B9619C0761B8A6F74CB346EB86CDDD`。
换版本要重建改造 APK，并重跑 `probe_sigset.py` / `probe_bind.py` 回归。

仓库不含任何设备 cookie / 账号凭据（`out/`、`samples/`、`work/` 全在 `.gitignore` 里；
`out/profile.json` 由 `tools/make_profile.py` 从你自己的设备现场生成）。

仅用于自有设备上的接口压力与数据完整性研究；采集数据请自行评估授权与用途。

MIT License