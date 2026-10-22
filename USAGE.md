# USAGE.md — php2shell_exp 参数总表

与 `php2shell_exp.py` argparse 定义逐项对应（子命令：`auto` / `check` / `exploit` / `shell` / `build`）。
调用约定：`python php2shell_exp.py <子命令> [目标] [参数]`。

---

## 1. 子命令总表

| 子命令 | 用途 | 网络行为 |
| --- | --- | --- |
| `auto` | 全自动流水线：指纹→防御识别→绕过→利用→后续→停火→JSONL 报告 | 主动 |
| `check` | 仅指纹（PHP 版本 + WAF 堆叠 + 补丁判定） | 被动 GET |
| `exploit` | 手动指定单链精确射击（已知路径时最小请求量） | 主动 |
| `shell` | **RCE 主接口**：`--cmd` 单次 / 省略则 stdin 逐行循环 | 主动 |
| `build` | 离线生成载荷体（Burp 重放/调试） | 无网络 |

## 2. 公共目标参数（auto / check / exploit / shell）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `URL`（位置参数） | — | 目标地址，http/https 均可；auto/check 可省略改用 `-f` |
| `-f, --file` | — | 批量目标清单（每行一个 URL，`#` 注释） |
| `--timeout` | 15.0 | 单请求超时秒 |
| `--verify-tls` | 关 | 校验 TLS 证书（默认关闭） |

## 3. WAF 绕过参数（auto / exploit / shell）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--bypass-level` | 3 | 绕过强度 0=off 1=基础 2=+头部 3=+传输/参数全开 |
| `--try-all` | 关 | 全量策略逐一自动尝试（多层堆叠/未知 WAF 用） |
| `--cookie` | — | 导入人工过挑战的会话 Cookie |
| `--warmup` | 关 | 预热采集 WAF 追踪 Cookie（acw_tc 等）复用 |
| `--solver-cmd` | — | 外部滑块/人机求解器命令（stdout 输出放行 Cookie 串） |
| `--jitter` | 2.0 | 射击间拟人抖动基数秒（触顶自动退避 ×1.5≤30s） |
| `--rounds` | 1 | 持续测试轮次（未确认前循环，命中即停） |
| `--sleep` | 5.0 | 轮次间隔秒 |
| `--seed-mode` | full | full=完整发送（默认；需 `cleanup=Off`，官方实测唯一可靠持久化路径）/ abort=在途窗口实验模式（8.2.34 实测上传中不写盘，窗口不存在） |
| `--seed-url` | — | 投毒端点完整 URL（handler 混淆链可与触发端点分属不同 vhost/端口实例，各自 INI 决定序列化器） |
| `--trigger-url` | — | 触发端点完整 URL（与 `--seed-url` 配对使用） |
| `--flag-cmd` | — | 绕过成功后的自动后续操作命令（如落地 flag） |
| `--flag-expect` | `hello word` | 后续操作成功判据 |

## 4. auto 专属参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--workers` | 8 | 批量并发 |
| `-o, --output` | report.jsonl | JSONL 结果（断点续跑，自动跳过已确认目标） |
| `--cmd` | `echo P2S_<token>` | 利用后执行命令（默认无害标记） |
| `--expect` | 自动推导 | 命中判定字符串（详见 §8 判据推导） |
| `--force` | 关 | 对指纹已修补目标也执行 |
| `--no-uaf` | 关 | 跳过 uaf 链 |
| `--max-attempts` | 64 | hijack 矩阵射击上限 |
| `--seed-path` / `--trigger-path` | 自动发现 | 精确指定投毒/触发端点（已知路径时可压到 2 请求） |
| `--seed-wordlist` | 内置 | seed 端点字典覆盖 |
| `--trigger-wordlist` | 内置 | trigger 端点字典覆盖 |
| `--gadget-wordlist` | 内置 | gadget 类名字典覆盖 |
| `--prop-wordlist` | 内置 | 属性名字典覆盖 |
| `--variant` | 全部 | `pipe_object`（\|前缀+强制失败尾，默认）/ `pipe_clean`（公开 PoC 原始格式）子集 |
| `--uaf-size-mb` | 12.0 | uaf 链 plant 载荷大小（需大于目标 `memory_limit`，见 §9） |
| `--stall` | 1.5 | uaf 链请求间停滞秒（同 worker 亲和窗口） |
| `--monitor-url` | — | lab 监控端点（armed 判定用） |

## 5. exploit 专属参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--chain` | hijack | `hijack` / `uaf` / `inject` |
| `--seed-path` | `/SEED_PATH` | 投毒端点 |
| `--trigger-path` | `/TRIGGER_PATH` | 触发端点 |
| `--gadget` / `--prop` | `GADGET` / `PROP` | gadget 类名 / 属性名 |
| `--cmd` | `COMMAND` | 执行命令 |
| `--expect` | 自动推导 | 判定串 |
| `--sid` | 随机 | 固定会话 ID |
| `--variant` | pipe_object | 进度值形态 |
| `--uaf-size-mb` | 12.0 | uaf 链 plant 载荷大小 |
| `--stall` | 1.5 | uaf 链请求间停滞秒 |
| `--monitor-url` | — | lab 监控端点 |

## 6. shell 专属参数（稳定通道）

通道建立（自动）：端点发现（未指定路径时）→ gadget/prop 探测 → 命令分隔符识别（sh `;` /
cmd.exe `&`）→ 标记限界通道。输出严格提取于 `__P2S_B/E_<tok>__` 之间；stderr 整链归并；
瞬时抖动自动重试；stdin 净化 BOM/零宽字符。

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--seed-path` / `--trigger-path` | 自动发现 | 投毒/触发端点 |
| `--gadget` / `--prop` | 自动探测 | gadget 类名 / 属性名（给出即固定，跳过探测） |
| `--cmd` | — | 单次执行命令；省略则从 stdin 逐行读取（`exit`/`quit` 退出） |
| `--expect` | — | 叠加判定串（通道自带标记判定，此参数额外校验） |
| `--json` | 关 | Agent 模式：首行通道信息 + 每命令一行 JSON |
| `--sid` | 随机 | 固定会话 ID |
| `--monitor-url` | — | lab 监控端点 |

## 7. build 专属参数

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--chain` | hijack | `hijack` / `uaf` / `inject` |
| `--cmd` | `COMMAND` | 载荷内命令 |
| `--gadget` / `--prop` | `GADGET` / `PROP` | gadget 类名 / 属性名 |
| `--sid` | 随机 | 会话 ID |
| `--variant` | pipe_object | 进度值形态 |
| `--size-mb` | 1.0 | uaf plant 载荷大小（`build --chain uaf`） |
| `-o, --output` | body.bin | 载荷体输出文件 |

## 8. 判据（expect）推导规则

1. 显式 `--expect` 优先；
2. 自定义 `--cmd` 且未给 `--expect`：`echo` 语句取重定向/管道前完整文本 + 末词
   （`echo hello word > flag.txt` → `hello word` / `word`），多词非 echo 命令取末词；
3. 默认命令（`echo P2S_<token>`）：以随机 token 判定；
4. `shell` 未给 `--expect`：追加标记 echo（`COMMAND; echo P2S_<token>`）判定，任意命令均有结构化 oracle。

命中红线：响应中命令输出**先于** `Failed to decode session object` 告警 = 命中；仅告警无输出 = gadget/属性不对；无告警 = 端点/处理器前提不满足。

## 9. uaf 链触发（CVE-2026-109619 真实机制）

三请求序列（santihabib ASAN 复现的 HTTP 化）：

| 步骤 | 动作 | 期望信号 |
| --- | --- | --- |
| plant | progress 值超大（无 `\|`/CR/LF）写入会话键 | 2xx |
| oom | 同会话再入 rfc1867 → 解码超大串 → OOM bailout → `BG(unserialize)` 悬垂 | 500 / `memory size … exhausted` |
| fire | 小会话再解码 → 复用悬垂指针 → `tmp_var` 读 `last_dtor` | 连接断 / 502 / 503 → `crash_signal` |

约束：`--uaf-size-mb` 需大于目标 `memory_limit`（公开 PoC：12MB/8M）；三请求需命中同一 worker
（FPM `pm.max_children=1` 或靠重试）；fire 会话必须小。**崩溃确定性、预认证；RCE 条件化**
（sink + ASLR 泄漏 + 堆排布），自动化只判 `crash_signal`。被取证证伪的“伪造 delta CALL_ADDR”机制已移除。

## 10. 退出码

| 码 | 含义 |
| --- | --- |
| 0 | RCE 确认（`rce_confirmed`） |
| 1 | 全部目标不可达 |
| 2 | 疑似：`likely_vulnerable_no_rce` / `crash_signal` / `armed` |
| 3 | 单链未命中（exploit / shell） |
| 4 | 无发现 / 无新任务 |

## 11. verdict 决策树

```
rce_confirmed        → 测试完成（flag_stage.rce_hit=true 即 flag 已落地）→ 停火
armed                → upload_progress 已激活 → exploit 换 gadget/变体续打
crash_signal         → CVE-2026-109619 崩溃触发命中（plant→OOM→悬垂复用）；RCE 需人工续做（sink+泄漏+堆排布）
challenge_blocked    → 人机验证 → --warmup / --cookie / --solver-cmd
post_blocked         → POST 方法策略封禁（post_block_codes）→ 加白/源站面/换出口
likely_vulnerable_no_rce → 版本面漏洞但链未中 → 扩 gadget 字典/指定真实路径重试
skipped_patched      → 已修补 → 跳过（除非 --force）
```

## 12. JSONL 输出契约（每行一个目标）

关键字段：`target`、`verdict`、`via`、`fingerprint`（banner/status/waf）、`defense`（layers/evidence/profile/depth）、
`discovery`、`chains[]`（chain/strategy/steps/rce_hit/decode_warning）、`adaptive`、`flag_stage`、`round`。
一键通杀辅助字段：`chain_prereq`（`present`=handler 混淆机制成立但 gadget 未命中 / `absent`=前提缺失）、
`chain_prereq_hint`（可执行修复指引）；`adaptive` 含 `prereq_absent_early_stop@N` 表示第 N 射提前止损。

`fingerprint.status` 取值：`patched` / `branch_only` / `likely_vulnerable` / `eol_affected`（5.4~8.1 EOL，官方无修复）/ `eol_or_unknown` / `no_php_version` / `unreachable`。
