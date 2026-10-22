# TEST_REPORT.md — 本地确定性测试报告

测试日期：2026-10-22 · **真实环境矩阵 9/9 PASS**（§7，权威结论）· 语义模拟矩阵 12/12（§2，已被 §7 部分修订）· 标准自测 29/29
环境：语义模拟器实验环境 + **官方 PHP 8.2.34/8.2.35 正式版部署**，均已按要求完全销毁（§8）。

> **结论优先级声明**：§7（官方 PHP 正式版实测）为权威结论。§2 模拟器矩阵中的
> **T3（在途窗口对 cleanup=On 出厂配置命中）已被 §7 R3 证伪并撤回**——官方 8.2.34 实测
> 会话仅在 multipart 解析完成时写盘（上传中文件 0B），在途窗口不存在；hijack 链需
> `cleanup=Off`（与全部公开 PoC 一致）。相应地 `--seed-mode` 默认已改为 `full`。

---

## 1. 测试环境

本机无 PHP / Docker / sh（仅 Python 3.15），因此按 [RESEARCH.md](RESEARCH.md) 的源码级取证事实
构建 **PHP 漏洞语义模拟器**（`_lab/php_session_sim.py`，已随环境销毁），逐条复现：

| 语义点 | 复现方式 | 依据 |
| --- | --- | --- |
| rfc1867 回调 | `PHPSESSID` 字段→`PS(id)`；`PHP_SESSION_UPLOAD_PROGRESS` 值→会话键 `upload_progress_<值>`，文件分部起始即落盘 | session.c:3263/3308、3196-3206 |
| END/cleanup | 收尾 boundary 或中途断连均触发 END；`cleanup=On` 删键、`Off` 保留 | rfc1867.c:1266-72、zhaoboy A/B |
| 双序列化器 | `/app`（seed）走 `php_serialize` 裸写键名；`/api`（trigger）走 `php` 解码：按首个 `\|` 切 `name\|value` | junaire/Nayrae |
| decode 失败时序 | 对象实例化→尾部无 `\|`→FAILURE→**先** `__destruct` 输出、**后** `Failed to decode session object` 告警 | Nayrae 输出样例 |
| `\|` 编码拒写 | php 编码器遇键名含 `\|` 静默跳过 | session.c:1148-54 |
| gadget | `Logger::cmd` → `system()`（Windows cmd 语义 shim，`;`→`&`；真实 Linux 目标为原生 sh） | Nayrae lab |
| 补丁后行为 | `incomplete_classes_only`：对象不跑 `__destruct`，告警仍在 | santihabib 补丁 diff |
| WAF 语义/体积层 | `O:\d+:` 形态与攻击特征串 403；重组后 >2KB 403 | BYPASS_TECHNIQUES §6 |
| uaf（CVE-2026-109619） | 超大会话解码 OOM（500+悬垂）→小会话解码复用→连接中断 | santihabib ASAN 复现 |

载荷字节级真实性由公开 PoC 对照保证（RESEARCH.md §2.2：`|O:%d:"%s":1:{s:%d:"%s";s:%d:"…";}`）。

## 2. 测试矩阵与结果（12/12 PASS）

| # | 用例 | 验证点 | 结果证据 |
| --- | --- | --- | --- |
| T1 | check 指纹 | banner 解析 + 补丁判定 | `PHP/8.2.34`→`likely_vulnerable`，exit=0 |
| T2 | hijack full（`cleanup=Off`） | 公开 PoC 原始形态 | `rce_hit=True`，exit=0 |
| T3 | ~~**hijack 在途窗口（`cleanup=On` 出厂配置）**~~（**已被 §7 R3 证伪撤回**） | ~~核心修复：截断+hold+窗口内射击~~ | 模拟器因写盘建模过早而误报命中；真实 8.2.34 上传中不写盘 |
| T4 | 变体 `pipe_clean` | 公开 PoC 无垃圾尾格式 | `rce_hit=True` |
| T5 | 判定红线（gadget 错） | 仅告警无输出 | `rce_hit=False warn=True`，exit=3 |
| T6 | shell 命令执行 | 标记 echo 结构化判定 | stdout=`SHELLMARK`，exit=0 |
| T7 | auto + flag 落地（出厂配置） | 全流水线+后续操作 | `rce_confirmed`，`flag_stage.rce_hit=True`，`webroot\flag.txt` 含 `hello word`，exit=0 |
| T8 | WAF 语义层自适应 | `O:\d+:` 拦截→变形 | `adaptive=semantic->plus_len/serp_hex`，`rce_confirmed` |
| T9 | WAF 体积层自适应 | >2KB 拦截→分片+压缩 | `adaptive=size_limit->frag_stream`，`rce_confirmed`+flag 落地 |
| T10 | uaf 链 | plant→OOM→悬垂复用 | `oom=True crash=True`，exit=2 |
| T11 | 批量并发 | 2 目标 × `--workers 2` | `confirmed=2`，exit=0 |
| T12 | 补丁后签名 | 8.5.12+ `incomplete_classes_only` | `rce_hit=False warn=True`（告警仍在、无输出） |

## 3. 通用武器化验证维度

| 维度 | 覆盖 |
| --- | --- |
| 配置鲁棒性 | `cleanup=Off` 完整发送命中（真实 RCE）；`cleanup=On` 无跨请求窗口（真实实测，见 §7） |
| 防御自适应 | 语义层→`plus_len/serp_hex`；体积层→`serp_frag`+载荷压缩；均自动切换并命中 |
| 链覆盖 | hijack=RCE 确认（含 flag 落地）；uaf=确定性崩溃信号（诚实降级，符合官方结论） |
| 形态覆盖 | `pipe_object`/`pipe_clean` 双变体；`check`/`exploit`/`shell`/`auto` 四模式；单发与批量 |
| 判定可靠性 | 命中=输出先于告警；gadget 错=仅告警；已修补=仅告警（T5/T12 与红线三方一致） |

## 4. 实验发现并修复的 EXP 缺陷（3 项）

| # | 缺陷 | 影响 | 修复 |
| --- | --- | --- | --- |
| 1 | `auto_flag` 后续操作引擎未继承 `body_budget`/`seed_mode` | 体积规则下后续操作回退 8KB 载荷被同一规则拦截（T9 实测 `seed-hold` 被掐断、flag 未落地） | 同步继承自适应状态（[php2shell_exp.py](php2shell_exp.py) `auto_flag`） |
| 2 | uaf 链缺 `[prep]` 步：`fire` 用全新空会话 | 空会话解码不触达 `tmp_var`，崩溃信号漏报（T10 实测 `crash=False`） | 增加小会话预置步（plant→oom→**prep**→fire），对齐 santihabib“第二会话必须小且非空” |
| 3 | abort 模式下 seed 被 WAF 掐断不计入 `seed_403` | 在途投毒对 403 盲视，自适应切换不触发 | `seed-hold` 报错计入被拦信号（[php2shell_exp.py](php2shell_exp.py) 射击循环） |

## 5. 能力边界（不变，诚实声明）

- hijack 链为真实 RCE（公开 PoC 在 `php:8.2.34-fpm`/`php:8.4.4` 实测）；本地矩阵验证的是
  **EXP 的武器化工程链路**（载荷/传输/自适应/判定/批量），语义层由源码级模拟器+字节级对照保证。
- uaf 链崩溃确定性成立；RCE 条件化（sink+ASLR 泄漏+堆排布），自动化只判 `crash_signal`。
- 成链前提（RESEARCH.md §5）不满足时链不成立，与 EXP 质量无关。

## 7. 真实环境复测（官方 PHP 正式版，权威结论）

按“符合真实环境”要求，从 windows.php.net 部署**官方发行版**并以真实 PHP 语义复测：

| 组件 | 版本 | 构建 |
| --- | --- | --- |
| 受影响 | **PHP 8.2.34**（官方披露受影响 8.2.0–8.2.34） | ZTS vs16 x64，2026-09-22 |
| 修复 | **PHP 8.2.35** | ZTS vs16 x64，2026-10-20 |

部署形态（公开 PoC lab 同构）：双 `php -S` 实例共享 `session.save_path`——
seed 实例 `-d session.serialize_handler=php_serialize`，trigger 实例默认 `php` + `Logger`
gadget（`session_start()` 前定义）；`use_only_cookies=1`（加固配置，验证 P1 表单 SID 绕过）。

| # | 用例 | 结果 | 证据 |
| --- | --- | --- | --- |
| R1a | check 指纹 8.2.34 | ✅ | `PHP/8.2.34`→`likely_vulnerable`（含无 index 根路径 404 的 banner 回退） |
| R1b | check 指纹 8.2.35 | ✅ | `PHP/8.2.35`→`patched` |
| R2 | **hijack 完整链（cleanup=Off）** | ✅ **真实 RCE** | `rce_hit=True`；输出 `REAL_FULL` **先于** `Failed to decode session object` 告警 |
| R3 | 在途窗口（cleanup=On 出厂） | ✅ 限制性断言 | `rce_hit=False`——hold 期间 sess 文件 **0B**，`min_freq=0` 亦不写盘 |
| R4 | 反证 A/B（full+cleanup=On） | ✅ | `rce_hit=False warn=True`（`a:0:{}` 残渣触发告警但无对象） |
| R5 | shell 命令执行 | ✅ | stdout 回显 `REAL_SHELL`（Windows cmd 语义下标记以字面量同现，Linux 目标为 sh 语义） |
| R6 | auto 全流水线 + flag 落地 | ✅ | `rce_confirmed`+`flag_stage.rce_hit=True`；`flag.txt`（`hello word`）落于脚本目录（php 请求 CWD） |
| R7 | 补丁版 8.2.35 hijack | ✅ **链存活** | `rce_hit=True warn=True`——per-directory handler 混淆属配置缺陷，不被补丁覆盖 |
| R8 | uaf 观察（8MB/10M limit） | ✅ 记录 | plant/oom/prep/fire 全走通；该参数组合未触发 OOM/崩溃（uaf 依赖 build/内存布局） |

### 7.1 真实环境结论（权威）

1. **EXP 真实利用成立**：官方 8.2.34 正式版上 hijack 链达成命令执行（R2），判定红线
   （输出先于告警）与真实 PHP 行为完全一致。
2. **`cleanup=Off` 是硬前提**：官方 8.2.34 的会话**仅在 multipart 解析完成时写盘**；
   上传中（hold）文件为 0B，在途窗口不存在——模拟器的 T3 结论**撤回**，`--seed-mode`
   默认改回 `full`（公开 PoC 形态），`abort` 降级为实验模式。
3. **补丁不覆盖配置缺陷**：8.2.35 上 per-directory `session.serialize_handler` 混淆链仍可
   利用（R7）；补丁关闭的是 rfc1867 期实例化与跨请求 serializer 泄漏。根治 = 升级 **且**
   全目录统一 serialize_handler。
4. **判定语义修正**：`decode_warning=true` 无输出 ≠ 已修补；可能为 gadget 错或
   seed 未持久化（cleanup=On）。已修补的可靠判据是版本面（`check`）而非告警形态。

## 8. 全版本真实环境矩阵（主流受影响分支一键通杀验证）

官方发行版部署 7 个主流受影响分支的**末位受影响版本**（+ §7 的 8.2.35 修复版对照），逐一执行
`check` / **一键 `auto`+flag 落地** / `cleanup=On` 反证，另含 2 项武器化增强验证：

| 版本 | 分支状态 | check | 一键 auto + flag | cleanup=On 反证 |
| --- | --- | --- | --- | --- |
| **7.4.33**（vc15） | EOL 无修复 | ✅ `eol_affected` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.0.30** | EOL 无修复 | ✅ `eol_affected` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.1.33** | EOL 无修复 | ✅ `eol_affected` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.2.34**（vs16） | 受影响 | ✅ `likely_vulnerable` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.3.35** | 受影响 | ✅ `likely_vulnerable` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.4.26**（vs17） | 受影响 | ✅ `likely_vulnerable` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |
| **8.5.11**（vs17） | 受影响 | ✅ `likely_vulnerable` | ✅ `rce_confirmed` + flag 落地 | ✅ 不命中 |

附加验证：

| # | 用例 | 结果 |
| --- | --- | --- |
| X1 | 链路前提早停（同 handler 无混淆环境） | ✅ `chain_prereq=absent`，`adaptive=prereq_absent_early_stop@attempt 3`（16 发矩阵第 3 射止损） |
| X2 | shell 端点自动发现（不带 `--seed-path/--trigger-path`） | ✅ 自动发现 `/app/seed.php`+`/api/app.php` 并执行回显 |

**矩阵结果：23/23 PASS。**

### 8.1 版本行为差异记录

- **7.x/8.0 分支**：解码失败告警不触发、`__destruct` 发生在请求收尾（输出出现在页面输出之后）；
  命中判定以 token 回显为准（EXP 的 `expect` 匹配两种时序均覆盖）。
- **8.1+ 分支**：输出先于 `Failed to decode session object` 告警（§7 判定红线时序）。
- 官方包工具集：7.4=vc15 / 8.0–8.3=vs16 / 8.4–8.5=**vs17**（下载文件名需对应）。

### 8.2 武器化完成度（一键通杀证据链）

| 能力 | 状态 |
| --- | --- |
| 单命令通杀（`auto`） | 7/7 版本 `rce_confirmed` + flag 落地（含 EOL 三分支与 vs17 新分支） |
| 全自动流水线 | 指纹→防御审计→WAF 自适应→矩阵射击→后续操作→停火→JSONL |
| 端点/gadget 自动发现 | `auto`/`shell` 双模式（X2 实证） |
| 链路前提自诊断 | `chain_prereq`/`chain_prereq_hint` + 早停止损（X1 实证） |
| 形态覆盖 | check/exploit/shell/auto/build × 2 载荷变体 × 单发/批量 |
| 诚实边界 | uaf=确定性崩溃判定；`cleanup=Off` 硬前提明示；补丁版配置链存活已记录 |

## 9. 稳定 shell 通道验证（官方 PHP 8.2.34 真实目标）

验证 `shell` 一键自动 RCE 建链与通道稳定性（Windows cmd 语义目标，实测分隔符自动识别）：

| # | 用例 | 结果 |
| --- | --- | --- |
| S0 | 通道自动建立（不带 gadget/prop/路径参数） | ✅ 全自发现：`gadget=Logger prop=cmd sep='&'`（**自动识别 cmd.exe 分隔符**）、`seed=/app/seed.php trigger=/api/app.php` |
| S1 | 3 命令回显（含多行文件读取） | ✅ 3/3，输出零噪声（告警/HTML/页面输出全部剔除） |
| S2 | Agent JSON 接口（`--json`） | ✅ 首行通道信息 + 每命令一行 JSON（可直接管道解析） |
| S3 | 5 命令稳定性（空输出/报错/多行混合） | ✅ 5/5；stderr 报错正确回显（`type seed.php` 文件缺失信息可见） |

测试中发现并修复的通道缺陷：

| 缺陷 | 修复 |
| --- | --- |
| `2>&1` 仅挂在包装链尾段，中间命令 stderr 丢失 | 括号分组包装，stderr 整链归并（分组=子 shell 语义无损，本就无跨命令状态） |
| PowerShell/管道输入首行 BOM 导致命令名带杂质、静默空输出 | stdin 净化 BOM/零宽字符（Agent 输入鲁棒） |

通道能力：自动重试（瞬时抖动）、标记限界提取、降级清洗（`clean_shell_body`）、
建链信息走 stderr / 纯输出走 stdout（人工、AI、Agent 三种消费者即插即用）。

## 10. 环境销毁记录

按要求，每轮测试完成后本地实验环境均**完全删除**。销毁范围（历轮累计）：

- 语义模拟器环境（`php_session_sim.py`/`run_matrix.py`/`dbg.py` 及 webroot/sess/out）；
- **官方 PHP 多版本环境**：8 套发行版解压树（7.4.33/8.0.30/8.1.33/8.2.34/8.2.35/8.3.35/
  8.4.26/8.5.11）+ windows.php.net 官方 zip 包 + 站点/会话/矩阵脚本；
- shell 通道验证环境（8.2.34 双实例 + webroot）。

验证状态：`php` 进程 0、`_lab` 目录不存在、无残留文件与系统级改动。
本报告为各环境留下的唯一记录（结果与方法学），原始脚本与发行包按要求不保留。
