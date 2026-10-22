# CHANGELOG — 更新日志

本项目变更记录，风格参照 [Keep a Changelog](https://keepachangelog.com/)。
版本策略：**V1.0.0 初版 + V1.0.1 统一更新**（截至本次的全部改进均归入 V1.0.1，不拆分多版本）。
日期为发布日（Asia/Shanghai）。

---

## [V1.0.1] - 2026-10-22

**统一更新**——真实环境验证、稳定 shell 通道、一键通杀与全版本矩阵（截至本次的全部改进）。

### 新增
- **稳定 shell 通道（自动 RCE 建链）**：`shell` 一条命令完成 端点发现 → gadget/prop 探测 →
  命令分隔符自动识别（sh `;` / cmd.exe `&`）→ 通道建立 → 交互/管道命令循环。
  - 标记限界输出提取（`__P2S_B/E_<tok>__` 括号分组）：告警/HTML/页面噪声天然剔除；
  - **stderr 归并**：分组包装使 gadget 的 `2>&1` 作用于整链，中间命令报错可回显；
  - 瞬时抖动自动重试；BOM/零宽字符输入净化（Agent/管道输入鲁棒）；
  - **Agent 接口**：`--json` 模式首行输出通道信息、此后每命令一行 JSON（人工/AI/Agent 通用）。
- **链路前提自诊断**：JSONL 新增 `chain_prereq`（present=gadget 问题 / absent=前提缺失）+
  `chain_prereq_hint` 修复指引；连续 3 发无命中无告警自动早停止损（`prereq_absent_early_stop@N`）。
- **双端点支持**：`--seed-url` / `--trigger-url`（handler 混淆链可跨 vhost/端口实例，公开 PoC 同款接口）。
- **`check` 指纹回退探测**（404 根路径无 banner 时尝试常见 PHP 页面）。
- 文档体系：`USAGE.md`（参数总表+JSONL 契约）、`RESEARCH.md`（联网取证+补丁逆向+真假利用对照）、
  `TEST_REPORT.md`（三层测试证据）、`tests/test_core.py`（36 项自测）。

### 变更
- `--seed-mode` 默认 `full`（公开 PoC 形态）；`abort` 降级实验模式。依据官方 8.2.34 实测：
  会话仅在 multipart 解析完成时写盘，**`session.upload_progress.cleanup=Off` 为 hijack 链硬前提**。
- 判定红线修正：`decode_warning` 无输出 ≠ 已修补（8.2.35 实测 per-directory 混淆链仍可利用）；
  版本面判定（`check`）才是补丁判据。影响面修正：5.4~8.1 EOL **官方无修复**。
- shell `--expect` 语义：通道自带标记判定，此参数为叠加校验。

### 修复
- 工程缺陷 12 项：uaf 载荷重复注入 32 次、多值 `Set-Cookie` 覆盖、chunked/gzip 未解码、
  `seed_403` 双重计数、expect 死候选、`uri_double_enc` 名实不符、shell 误判、版本判定、
  CALL_ADDR 盲猜、模块级泄漏、`chain_uaf` expect `TypeError`、SKILL 文档漂移。
- 真实环境/实验发现 8 项：`auto_flag` 未继承自适应状态、uaf 缺 `[prep]` 步、abort 对 403 盲视、
  在途窗口结论撤回（`full` 默认化）、shell 标记行过宽剔除、`chain_prereq` 分支误挂、
  矩阵执行器 cleanup 配置、**通道 stderr 丢失**（分组包装修复）。
- 移除被证伪机制：`bare_object` 裸对象变体、伪造 delta CALL_ADDR uaf 链、"裸断连持久化"。

### 验证
| 层级 | 结果 |
| --- | --- |
| 标准自测 | 36/36 |
| 语义模拟矩阵 | 12/12 |
| 单版本真实环境（官方 8.2.34 + 8.2.35 对照） | 9/9 |
| **全版本真实矩阵（7.4.33/8.0.30/8.1.33/8.2.34/8.3.35/8.4.26/8.5.11）** | **23/23**（7/7 一键通杀+flag 落地） |
| **稳定 shell 通道** | 自动建链（gadget/prop/sep/端点全自发现）· 3+5 命令全回显 · stderr 归并 · Agent JSON |

### 发布
- 文档按最终代码全面精确化：README 增补 **EXP 支持攻击的 PHP 版本矩阵** 与版本号 V1.0.1；
  参数表与 argparse 逐项对齐（含 `--seed-url/--trigger-url`/`--json`/`--uaf-size-mb` 等）；
  脚本内置 `__version__ = "V1.0.1"`。
- GitHub Release：`v1.0.1`（tag + Release Notes）。

---

## [V1.0.0] - 2026-10-21

**初始公开版**。

### 新增
- `php2shell_exp.py`：单文件、纯标准库、零交互 EXP（Python 3.8+）。
- 子命令：`auto`（全自动流水线）/ `check`（被动指纹）/ `exploit`（单链精确射击）/
  `shell`（RCE 主接口）/ `build`（离线出包）。
- 利用链：hijack（会话投毒 + serialize_handler 混淆 → `__destruct`）/ uaf / inject。
- 防御识别 6 层画像 + 20+ 绕过策略 + 13 种 WAF 指纹模板。
- 自动化契约：JSONL 报告、退出码分级、断点续跑、命中停火、`--flag-cmd` 后续操作。
- 文档：`Readme.md`（含免责声明）、`BYPASS_TECHNIQUES.md`、`skills/php2shell-exp/SKILL.md`。

---

### 参考入口

- 机制依据与差异对照：[RESEARCH.md](RESEARCH.md)
- 测试证据（模拟器 12/12 + 真实 9/9 + 全版本 23/23 + shell 通道）：[TEST_REPORT.md](TEST_REPORT.md)
- 参数现状：[USAGE.md](USAGE.md)
- 变更自测：`python -m unittest discover -s tests`
