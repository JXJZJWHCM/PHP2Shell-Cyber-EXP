# RESEARCH.md — PHP2Shell 联网取证与补丁逆向分析报告

> 目的：对照 GitHub 公开 PoC 与 PHP 官方补丁，逐条验证 `php2shell_exp.py` 的利用链是否**真实成立**，
> 并把被证伪的机制从 EXP 中剔除。取证时间：2026-10-22。所有结论标注来源；源码行号来自公开仓库转述。

---

## 0. 结论速览

| 利用链 | 真实性判定 | 依据 | EXP 处置 |
| --- | --- | --- | --- |
| hijack（handler 混淆 → `__destruct`） | ✅ **真实 RCE**（8.2.34-fpm / 8.4.4 实测 `uid=0`） | junaire / Nayrae / zhaoboy 实测 | payload 字节级对齐公开 PoC；投毒流程重写 |
| uaf（CVE-2026-109619 悬垂全局） | ✅ 崩溃确定；⚠️ RCE **条件化** | santihabib ASAN 复现 + 补丁 diff | 整链重写为真实三请求触发，只判 `crash_signal` |
| inject（P1+P2 会话文件写入） | ✅ 落盘真实；RCE 需 LFI sink | zhaoboy 端到端（`<?php?>` 入 sess 文件） | 保留为 P1+P2 标记原语，明示 LFI 前提 |
| ~~裸断连保 seed（cleanup=On）~~ | ❌ **证伪** | zhaoboy A/B：END 无条件触发，cleanup=1 → 0B | ~~在途窗口~~亦被实测证伪（上传中不写盘）；**`cleanup=Off` 为硬前提** |
| ~~`bare_object` 裸对象变体~~ | ❌ **证伪**（无 `\|` 无法实例化） | `ps_srlzr_decode_php` 按 `name\|value` 切分 | 移除，补 `pipe_clean` 真变体 |
| ~~伪造 delta CALL_ADDR uaf 链~~ | ❌ **证伪**（同类 kit 已被取证打假） | zhaoboy §3.4：“wrong delta OOMs/crashes a worker (DoS) not RCE” | 整链移除 |

---

## 1. 取证来源（一手）

| # | 来源 | 类型 | 关键结论 |
| --- | --- | --- | --- |
| 1 | [Nayrae/CVE-2026-109618](https://github.com/Nayrae/CVE-2026-109618) | 可工作 PoC + Docker lab | `\|` 前缀 + `O:6:"Logger":1:{s:3:"cmd";s:2:"id";}` 投毒；lab 必须 `cleanup=Off`；**命令输出先于 `Failed to decode session object` 告警**；去掉尾部数据 gadget 可能永不触发 |
| 2 | [junaire/CVE-2026-109618-exploit](https://github.com/junaire/CVE-2026-109618-exploit) | exploit.py（8.2.34-fpm + ASAN 实测） | 字节级 payload：`O:%d:"%s":1:{s:%d:"%s";s:%d:"…";}`；“Trailing container data → decode FAILURE → var_destroy → `__destruct` runs **inside** `session_start()`” |
| 3 | [AsviS/PHP2Shell](https://github.com/AsviS/PHP2Shell) | 验证 PoC + 分析 | 5 项发现：①`__destruct` 在 decode **FAILURE** 触发（handler 混淆 + trailing data）；②`PHPSESSID` 表单字段绕过 `use_only_cookies`（PR #22113）；③文件名原样入会话；④`PS(serializer)` 不随 RSHUTDOWN 重置；⑤var_destroy 再入 UAF |
| 4 | [mahumadad/php2shell-analysis](https://github.com/mahumadad/php2shell-analysis) | 全链分析 + 检测规则 | CVE 映射：**109618 = `PS(serializer)` 泄漏 + decode 失败 `__destruct`**（不依赖 upload_progress）；109619 = cached `zval*` UAF；5 条攻击链总表 |
| 5 | [santihabib/CVE-2026-109619](https://github.com/santihabib/CVE-2026-109619)（[ANALYSIS.md](https://github.com/santihabib/CVE-2026-109619/blob/main/docs/ANALYSIS.md)） | ASAN 复现 + 补丁逆向 | **109619 = `BG(unserialize)` 跨请求悬垂**（multipart 回调先于 `PHP_RINIT(basic)`；OOM bailout 跳过 `PHP_VAR_*_DESTROY`）；崩溃确定性、预认证；**RCE 条件化（sink+泄漏+堆排布）**；补丁 = `php_basic_early_rinit()` + `incomplete_classes_only` |
| 6 | [zhaoboy9692/CVE-2026-109618_](https://github.com/zhaoboy9692/CVE-2026-109618_) | 端到端实测（PHP 8.4.4 `uid=0`）+ **取证纠错** | ①`MULTIPART_EVENT_END` **无条件触发**（rfc1867.c:1266-72 `fileupload_done`），**含中途断连**；②A/B：cleanup=1 → 0B 文件（seed 不能持久化）；③文件名载体被 `getword`/`getword_conf` 在引号/分号处截断，**progress 值才是可靠载体**；④`\|` 是 php 编码器的显式拒写约束（session.c:1148-54）；⑤伪造 delta 调用链 kit 被证伪 |
| 7 | [hypnguyen1209/php2shell](https://github.com/hypnguyen1209/php2shell) | 3 阶段内存利用 | OOM → `PS(id)` 悬垂 → Set-Cookie 泄漏 → 假 HashTable `pDestructor=zif_system`；偏移 build 相关（`php:8.4.26-apache`）；命令 ≤14 字节 |
| 8 | [Upwind 初始评估](https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619) / [Logpresso 公告](https://www.logpresso.com/en/blog/2026-10-21-php2shell-security-advisory) | 厂商/社区公告 | 影响 PHP 5.4.0 起；补丁 2026-10-21 发布，**仅 8.2/8.3/8.4/8.5 分支**（8.2.35/8.3.36/8.4.27/8.5.12） |

PHP 官方：GHSA-6wmf-4rv5-p3rp（CVE-2026-109619，"RCE via stale global state"）、
GHSA-w8hw-w9fx-79w（CVE-2026-109618，"RCE via OOM corruption"）；8.5.12 changelog："Avoid state corruption via bailout"。

---

## 2. 漏洞机制（源码级归纳）

### 2.1 攻击面

`php_session_rfc1867_callback`（`ext/session/session.c`）在 multipart POST 解析期执行，
**早于** `PHP_RINIT(basic)` 与应用代码。两个关键副作用：

1. `PHPSESSID` 表单字段直接写入 `PS(id)`（session.c:3263/3308）——**绕过 `session.use_only_cookies=On`**
   （SID 字符集约束 `[a-zA-Z0-9,-]` 来自 `ps_files_open`，mod_files.c:165）。
2. `PHP_SESSION_UPLOAD_PROGRESS` 表单值原样成为会话键 `upload_progress_<值>`
   并在 update() 时序列化进 `sess_<sid>`（session.c:3196-3206）。

### 2.2 hijack 链（真实 RCE，本 EXP 主链）

前提：seed 目录 `session.serialize_handler=php_serialize`、trigger 目录默认 `php`、共享 `save_path`；
trigger 端点在 `session_start()` 前定义 gadget 类。

```
[seed]  POST(php_serialize 目录)：PHPSESSID=<sid>（表单字段）
        + PHP_SESSION_UPLOAD_PROGRESS = |O:6:"GADGET":1:{s:3:"PROP";s:LEN:"CMD";}<尾部垃圾>
        + 文件分部
        -> 会话文件（php_serialize 格式）：
           a:1:{s:N:"upload_progress_|O:6:"Logger":1:{…}…";a:5:{…进度数组…}}
[fire]  GET(php 目录) + Cookie: PHPSESSID=<sid>
        -> session_start() 用 php 解码器按首个 '|' 切分：
           name="a:1:{s:N:"upload_progress_"  value=O:6:"Logger":…  <- 对象实例化！
        -> 对象后余下数据无 '|' -> decode FAILURE
        -> php_session_cancel_decode() -> php_session_destroy()
        -> 注入对象 __destruct() 执行命令
        -> 之后才输出 Warning: session_start(): Failed to decode session object
```

判定红线（多源一致）：**命令输出先于告警 = 命中**；仅告警无输出 = gadget/属性不对
**或目标已修补**（见 §3）；无告警 = 端点/处理器前提不满足。

字节级 payload（junaire `rce_payload()`）与本 EXP `php_serialize_object()` 完全一致：
`O:6:"Logger":1:{s:3:"cmd";s:2:"id";}`，前缀 `|` 必需（缺 pipe 时对象不落在 value 位，**无法实例化**）。

### 2.3 cleanup 语义（关键纠错 + 真实环境实测修正）

zhaoboy 源码取证：`MULTIPART_EVENT_END` 在 rfc1867.c:1266-72（`fileupload_done`）**无条件触发**——
包括收尾 boundary 解析完成、`max_multipart` bail、**中途客户端断连**。cleanup=On 时
`php_session_rfc1867_cleanup` 随即删除投毒键（A/B：cleanup=1 → 0B 文件）。

**官方 PHP 8.2.34 正式版本地部署实测（TEST_REPORT §7）**：

| 观测 | 结果 |
| --- | --- |
| 完整发送（cleanup=Off） | 会话 465B 落盘，`__destruct` 输出**先于**告警（RCE 成立） |
| hold 期间（截断+慢发+连接保持） | sess 文件 **0B**；`min_freq=0` 亦然——**上传中途不写盘** |
| 写盘时机 | **multipart 解析完成时刻**（发送 0-chunk 后、连接仍保持时即可见），与连接关闭无关 |
| cleanup=On | 写盘与删键同在解析结束的同一请求内完成 → **无跨请求窗口** |

结论（**修正本节早期推断**）：在途窗口（hold-open）在官方 8.2.34 上**不成立**——
`session.upload_progress.cleanup=Off` 是 hijack 链的**硬前提**，与全部公开 PoC 一致
（Nayrae：“`cleanup=Off` is **Critical**”）。本 EXP `--seed-mode` 默认 `full`（公开 PoC 形态）；
`abort` 保留为**实验模式**（仅当 SAPI 在上传中 flush 会话时可能有效，迄今未在实测环境观察到）。

### 2.4 uaf 链（CVE-2026-109619 真实机制）

santihabib ASAN 复现（8.5.11）：

```
[plant] 向 save_path 写入超大会话（HTTP 化：progress 值超大 -> 会话键超大）
[oom]   同会话再入 rfc1867 回调 -> php_session_decode -> php_var_unserialize
        分配超大结构触顶 memory_limit -> zend_bailout 跳过 PHP_VAR_UNSERIALIZE_DESTROY
        -> BG(unserialize) level=1 + 悬垂指针（请求堆已释放，worker 存活，HTTP 500）
[fire]  小会话再解码（必须小，否则先 OOM 再触达悬垂）-> 复用悬垂指针
        -> tmp_var 读 (*var_hashx)->last_dtor -> SIGSEGV（worker 崩溃）
```

- 可达性：任何收 multipart 的端点、预认证、无需 `session_start()`。
- **崩溃确定性；RCE 条件化**（advisory 原文 high-complexity：需 producer/consumer 同 worker、
  sink、ASLR 泄漏、堆排布）。自动化只判 `crash_signal`，不做 RCE 承诺。
- 修复：8.5.12 新增 `php_basic_early_rinit()`（`php_request_startup()` 中先于
  `sapi_activate()`/`php_hash_environment()` 重置 `BG(serialize_lock)`/`BG(serialize)`/`BG(unserialize)`）。

### 2.5 inject 链（P1+P2，LFI 前置）

zhaoboy 端到端（PHP 8.4.4）：progress 值写入 `<?php … ?>` → 原样进 `sess_<sid>` →
应用 `include($path)` sink 命中即 RCE。载体约束：值中**无 `|`**（php 编码器拒写，
session.c:1148-54）、**无 CR/LF**；引号/括号/空格/分号可存活。cleanup=On 时仅请求存活期存在。
本 EXP `chain_inject` 即 P1+P2 标记写入 + fixation 检查，`lfi_needed=true` 明示升级条件。

### 2.6 WAF 绕过变体的 PHP 语义验证

| 变体 | PHP 语义 | 来源 |
| --- | --- | --- |
| `O:+N:`（plus_len） | 成立：unserialize 长度解析接受 `+` 号，经典 `/[oc]:\d+:/i` 过滤绕过 | 多篇公开 WP（如[攻防世界 Web_php_unserialize](https://developer.aliyun.com/article/1584935)） |
| `S:N:"\xx…"`（serp_hex） | 成立：`S:` 转义串类型自 PHP 5.2.1 进入 unserialize() | [WP trac #17375 讨论](https://lists.wordpress.org/pipermail/wp-trac/2011-June/116901.html) |
| 文件名载体 | **不可靠**：`getword`/`getword_conf` 在引号/分号处截断 | zhaoboy §3.3 |

---

## 3. 官方补丁逆向（8.5.12 / 8.4.27 / 8.3.36 / 8.2.35）

| 补丁元素 | 位置 | 作用 | 关闭的链 |
| --- | --- | --- | --- |
| `php_basic_early_rinit()` | `main/main.c`（`php_request_startup()` 早于 `sapi_activate()`） | 重置 `BG(serialize_lock)`/`BG(serialize)`/`BG(unserialize)`，URL 扫描器复位前移 | 109619 悬垂全局复用 |
| `incomplete_classes_only`（`PS(in_rfc1867_update)` 期间） | `ext/session/session.c`、`ext/standard/var.c`、`ext/standard/var_unserializer.re` | upload-progress 期解码出的对象一律 `__PHP_Incomplete_Class`，**不跑 `__wakeup`/`__unserialize`/`__destruct`** | handler 混淆 → `__destruct`（本 EXP hijack 链） |
| `ZEND_HAS_OOM()` / delayed-hard OOM | diff | 修 longjmp 状态破坏 | 109618 OOM 腐蚀 |

**补丁后签名**（santihabib 实测）：handler 混淆复现中**告警仍出现，但 `__destruct` 不执行、命令不执行**。

**本地实测补充（官方 8.2.35 正式版，TEST_REPORT R7）**：以脚本期 `session_start()` 触发的
per-directory handler 混淆链在补丁版上**仍可利用**（`__destruct` 正常执行、命令执行）——
补丁关闭的是 rfc1867 期实例化与跨请求 `PS(serializer)` 泄漏两条路径；**目录级
`session.serialize_handler` 不一致属配置缺陷，不被补丁覆盖**（与 4B3R4M4 链 A 注记
“works on patched PHP?: yes”一致）。→ 判读含义修正：`decode_warning=true` 而无输出
= gadget 错 或 seed 未持久化（`cleanup=On`）；**不能单凭告警断定已修补**。根治需升级
**且**全目录统一 `session.serialize_handler`。
**EOL 分支（5.4~8.1）无官方修复，永久受影响。**

---

## 4. EXP 差异对照与处置（本轮修复）

| # | 修复前 EXP 行为 | 取证结论 | 处置 |
| --- | --- | --- | --- |
| 1 | `--seed-mode abort`：“不发终止块并断开 → cleanup 不执行 → seed 持久化” | END 无条件触发（含断连）；cleanup=1 → seed 被删 | **重写为在途窗口**（截断+hold+窗口内射击）→ 官方 8.2.34 实测：**窗口不存在**（会话仅在解析完成时写盘），V1.0.1 默认改回 `full`、`abort` 降级实验模式 |
| 2 | `bare_object`（无 `\|` 裸对象）参与自动轮射 | 无 pipe 时对象不落 value 位，永不实例化（纯浪费射击） | **移除**；补 `pipe_clean`（公开 PoC 原始格式，靠容器尾强制失败） |
| 3 | uaf 链 = 伪造 zval + delta 表猜 CALL_ADDR + 停滞竞争 | 同类 kit 被取证打假：“wrong delta OOMs/crashes (DoS) not RCE” | **整链移除**，重写为 109619 真实三请求触发（plant→OOM→悬垂复用），只判 `crash_signal` |
| 4 | （计划中）文件名载体变体 | `getword` 截断引号/分号 | **不实现**，只保留值载体 |
| 5 | README 称 7.4/8.0/8.1“官方提供最小源码 backport” | 官方补丁仅 8.2+；EOL 无修复 | 文档修正；`check` 的 `eol_affected` 语义改为“EOL 无官方修复” |
| 6 | 判定红线：“仅告警无输出 = gadget/属性不对” | 补丁后也呈现该签名 | 红线补充第三种可能（已修补） |
| 7 | payload 构造（`O:%d:"%s":1:{…}` + `\|` 前缀 + 尾部垃圾） | 与 junaire/Nayrae 字节级一致；尾部垃圾是 decode 失败的确定性保障 | **保留**（本就正确，回归测试固化） |

---

## 5. 成链前提清单（严格版）

1. `session.upload_progress.enabled = On`（默认）；
2. seed 目录 `session.serialize_handler = php_serialize`（`\|` 拒写约束决定），trigger 目录默认 `php`
   （或 FPM worker 残留 `PS(serializer)` 的泄漏型瞬时混淆，mahumadad 链 3）；
3. 共享 `session.save_path`；
4. trigger 端点在 `session_start()` 之前定义 gadget 类（或 autoload/preload）；
5. `session.use_strict_mode = 0`（默认；=1 会拒绝攻击者指定 SID）；
6. `session.upload_progress.cleanup = Off`（**硬前提**，公开 PoC lab 均设 Off）——实测
   cleanup=On 时投毒键的写盘与删键同在解析结束的同一请求内完成，无跨请求利用窗口；
7. SID 字符集 `[a-zA-Z0-9,-]`（rand_sid=32 hex ✓）。

## 6. 能力边界（诚实声明）

- **hijack 链**：真实 RCE，公开 PoC 在 `php:8.2.34-fpm`、`php:8.4.4` 实测命令执行；
  前提（§5）不满足时链不成立（与 EXP 质量无关）。
- **uaf 链**：真实、预认证、崩溃确定（`crash_signal`）；RCE 需 sink + ASLR 泄漏 + 堆排布
  （hypnguyen 的完整利用偏移绑定 `php:8.4.26-apache` 单一 build），自动化不做虚假 RCE 判定。
- **inject 链**：P1+P2 落盘真实；升级 RCE 需应用侧 `include`/`require` sink（LFI）。

## 7. 引用

- https://github.com/Nayrae/CVE-2026-109618
- https://github.com/junaire/CVE-2026-109618-exploit
- https://github.com/AsviS/PHP2Shell
- https://github.com/mahumadad/php2shell-analysis
- https://github.com/santihabib/CVE-2026-109619 （docs/ANALYSIS.md）
- https://github.com/zhaoboy9692/CVE-2026-109618_
- https://github.com/hypnguyen1209/php2shell
- https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619
- https://www.logpresso.com/en/blog/2026-10-21-php2shell-security-advisory
- https://bugs.php.net/bug.php?id=79221 （rfc1867 回调 `MULTIPART_EVENT_END`/cleanup 结构）
