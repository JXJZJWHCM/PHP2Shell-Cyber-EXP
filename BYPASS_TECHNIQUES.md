# WAF 与防御技术绕过技术文档（php2shell EXP 配套）

版本：1.1 · 实证标注：✅=目标实测通过（403→404/200）· 🧪=技术成立待环境验证 · 📚=业界已知手法收录 · ❌=已证伪/不可用（依据 RESEARCH.md 取证）

---

## 0. 方法论：四层对抗模型

```
传输层(怎么发) → 语法层(发什么形态) → 语义层(载荷怎么变形) → 行为层(何时发/发多快)
```
任何一层失守即被拦；绕过必须四层协同。EXP 的 `BypassEngine` 即按此组织。

## 1. 语义层：序列化特征绕过（php2shell 核心）

### 1.1 `plus_len` — 长度 `+` 号注入 ✅
- **目标规则**：`/O:[0-9]+:/` 类对象注入正则（阿里云语义引擎实测命中完整 `O:\d+:"...":\d+:{...}`）。
- **手法**：`O:6:"Logger":1:{...}` → `O:+6:"Logger":1:{...}`（`C:`/`O:` 同理）。
- **PHP 语义**：unserialize 长度解析接受 `+` 号（公开 WP 验证的 `/[oc]:\d+:/i` 正则绕过标准手法，见 RESEARCH.md §2.6）。
- **实测**：A1-A5 变体全 404 放行，原始对象 403；完整利用形态（SID+progress+对象+文件分部）404。
- **变体**：`O:+06:`（前导零+符号双变体）、`C:+N:` custom 型。

### 1.2 `serp_hex` — `S:` 十六进制转义串 ✅
- **目标规则**：属性/值内容特征（如 `s:3:"cmd"`、命令关键词）。
- **手法**：`s:3:"cmd";s:2:"id";` → `S:3:"\63\6d\64";S:2:"\69\64";`。
- **PHP 语义**：`S:` 转义类型自 PHP 5.2.1 支持（php_var_unserialize）。
- **实测**：与 `plus_len` 叠加 A2/A3/A4 全 404。

### 1.3 其他语义变形（收录）
- 类名大小写混排（PHP 类查找不敏感，`logger` 等效 `Logger`）🧪
- `a:N:{i:0;O:...}` 数组嵌套包装（改变上下文特征）📚
- 尾部垃圾强制 decode-failure（利用需要，同时干扰规则锚定）✅

## 2. 语法层：multipart/HTTP 解析器差异

| 手法 | 机制 | 实测 |
| --- | --- | --- |
| `serp_frag` 特征跨分片切分 | 流式检测引擎不重组 → 规则看不到完整特征；PHP 侧重组语义不变 | ✅ T1（403→404）、8KB 分片（404/200） |
| `ct_case` 大小写 CT | `Multipart/Form-Data; Boundary=` WAF 正则大小写敏感、PHP `strncasecmp` 不敏感 | 🧪 |
| `ct_space` 空白/参数干扰 | `multipart/form-data ; charset=UTF-8; boundary="..."` | 🧪 |
| `bnd_long` 超长 boundary | 56+ 位随机串干扰规则特征 | 🧪 |
| `junk_field` 伪装普通表单 | 前置 `submit=1`/`MAX_FILE_SIZE` | 🧪 |
| `hpp` 参数污染 | 字段双写（部分 WAF 只检首现） | 🧪（阿里云双 name 拦截，需按指纹用） |
| `disorder` 字段乱序 | 文件分部前置/字段反转 | 🧪 |
| `expect_100` | `Expect: 100-continue` 走不同解析分支 | 🧪（EXP 已修 1xx 中间响应解析） |
| boundary 浏览器化 | `----WebKitFormBoundary<16 alnum>`；`----php2shell*`/CVE 串为已知 IoC | ✅ 必改项 |
| 双 name/无引号/单引号/obs-fold | WAF 与 PHP 的 name 参数解析差异 | ❌ 阿里云均拦（保留给其他 WAF） |

## 3. 传输层

| 手法 | 机制 | 实测 |
| --- | --- | --- |
| chunked 分片（FRAGMENT） | 无 Content-Length，体积规则按整包失效 | ✅ 8KB 总量过 ~2KB 规则 |
| `chunked_frag` 512B 慢发 | 分片+延迟规避流式特征窗口 | ✅（部分边缘400/断连，按指纹用） |
| 微型载荷 | 载荷体压至阈值下（body_budget 96B） | ✅ |
| `http10` / `abs_uri` / `lower_hdr` | 协议怪癖绕解析器一致性 | 🧪 |
| URI 变形：双重编码/`%2e`/`//`/`/./`/大小写/`;`/PATH_INFO/尾斜杠 | 路径规则绕过 | 🧪（EXP 全内置） |
| 在途窗口投毒（截断收尾 boundary + chunked 不终止） | 理论上借“上传中”窗口绕过 `cleanup=On` 的跨请求删键 | ❌ 实测不可用（官方 8.2.34 上传中不写盘，见 §6） |

## 4. 行为层：机器学习/异常预算对抗

**模型画像（实测）**：突发/异常预算型——同形态高频探测触顶→临时全拦；静默窗口→恢复。
证据：F 系列 6 连过 → G 同形态 4 连拦 → **暂停 20s → H 全过（404）**。

| 手法 | 机制 | EXP 实装 |
| --- | --- | --- |
| 拟人抖动 | 射击间隔随机 `U(jitter, 2*jitter)` | `--jitter`（默认 2s，建议 8s） |
| 诱饵流量 | 每 3 射夹带干净 GET/POST，稀释异常占比 | ✅ 自动 |
| 自动退避 | 通过后再次触顶 → jitter×1.5 递增（≤30s） | ✅ 自动 |
| 多形态轮换 | 每射变换 boundary/分片/CT/字段形态，规避特征漂移 | ✅ 12+ 变体 |
| 低速窗口化 | 轮次+长间隔，等预算窗口衰减 | `--rounds N --sleep S` |
| 浏览器指纹一致性 | UA/Referer/Sec-Fetch/Accept-Language 全套 | `junk_headers`/`warmup_cookie` |
| 会话复用 | 追踪 Cookie（acw_tc 等）预热复用 | `--warmup` |
| 人机挑战 | 滑块/JS 挑战求解器接入 | `--solver-cmd`/`--cookie` |

## 5. 各 WAF 专项（EXP 自动选择）

| WAF | 指纹标记 | 首选序列（节选） | 备注 |
| --- | --- | --- | --- |
| 阿里云 WAF/ESA | aliyun_waf_aa/acw_tc/captchaV2/X-Tengine-Error | serp_frag→warmup_cookie→plus_len/serp_hex | 语义/体积/行为三规则并存，实测最全 |
| 南墙 NQWAF | nqwaf/X-NQ-WAF | plus_len→serp_hex→uri_double_enc→hpp→ct_case | nginx+lua，规则正则为主，编码族有效 |
| 宝塔 bt_panel | X-BT-/aaWAF/bt_waf | plus_len→serp_hex→ct_space→hpp→bnd_long | 参数解析宽松，CT/boundary 变形族有效 |
| 多层堆叠 | ≥2 指纹命中 | **ALL_STRATEGIES 并集逐一尝试** | `--try-all` 强制全量 |
| Cloudflare | cf_chl_/__cf_bm | warmup_cookie→ua_crawler→chunked_frag | 挑战 Cookie 优先 |
| ModSecurity | mod_security | uri_double_enc→hpp→chunked_frag | CRS 正则编码绕过族 |
| 安全狗/云锁 | Safedog/yunsuo | 按 stacked 序列 | 组合变形 |

## 6. 已证伪/低效手法（保留记录，避免重复踩坑）

| 手法 | 结论 | 证据 |
| --- | --- | --- |
| 自然化内容/熵填充 | 对阿里云语义引擎无效 | 自然语料/随机hex 4KB 全 403 |
| boundary 命名规避（单独用） | 不足 | php2shell/WebKit 对照同 403（体积规则主导时） |
| Cookie 复用过滑块 | 追踪 Cookie 不等于验证通过 | acw_tc 复放仍挑战 |
| 双 name/单引号/obs-fold name | 阿里云全拦 | E2/E3/E6/E8 |
| 随机分片形态变异（持续） | 自适应规则消化后 10/10 拦 | morph 系列 |
| 纯 `S:` 变形（不加 `+`） | 头部特征仍在 | V1/V2 403 |
| 裸对象/无 `\|` 变体 | 对象不落 `name\|value` 的 value 位，永不实例化 | zhaoboy/junaire 取证（ps_srlzr_decode_php 切分语义） |
| 裸断连保 seed（cleanup=On） | `MULTIPART_EVENT_END` 无条件触发（含中途断连），投毒键照删 | zhaoboy A/B：cleanup=1 → 0B 文件 |
| 文件名载体注入对象 | `getword`/`getword_conf` 在引号/分号处截断 | zhaoboy §3.3 |
| 伪造 delta CALL_ADDR 调用链 | 错误 delta 只致 DoS（OOM/崩溃），非 RCE | zhaoboy §3.4 取证打假 |
| 在途窗口投毒（hold-open 过 cleanup=On） | 上传中途不写盘：官方 8.2.34 hold 期间 sess 文件 0B（`min_freq=0` 亦然），窗口不存在 | 官方 PHP 8.2.34 正式版实测（TEST_REPORT §7 R3） |

## 7. 检测方视角（蓝队附录）

1. IoC：boundary 含 CVE/工具名、`O:\d+:"`/`O:+\d+:"` 出现在表单值、`PHP_SESSION_UPLOAD_PROGRESS`
   值以 `|` 开头或含 `TRAILING_GARBAGE`、`PHPSESSID` 走表单字段、`S:` 转义串、
   `Failed to decode session object` 日志聚集、sess 文件含 `<?php`。
2. 纵深：WAF 语义规则补 `O:[+-]?\d+:` 变体；体积规则按重组后总量；行为模型对分片形态做重组后评分；
   会话文件完整性监控（键名含 `\|` 即告警）。
3. 根治：升级 PHP 8.5.12/8.4.27/8.3.36/8.2.35；5.4~8.1 EOL 无官方修复，迁移或以
   `session.upload_progress.enabled=Off` + 全目录统一 `session.serialize_handler` 加固。
