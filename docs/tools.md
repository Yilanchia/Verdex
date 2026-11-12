# Verdex Tool Reference · 工具参考

Verdex exposes **35 read-only tools** over MCP (stdio + JSON-RPC 2.0). Every tool:

- returns a JSON object with a `schema` / `tool` marker and `limitations`;
- is **text-only**: no tool sends a network request, executes a target, attaches to a process, or injects code;
- is annotated for MCP hosts: `destructiveHint:false` and `openWorldHint:false` on all tools; artifact writers are honestly marked `readOnlyHint:false`.

Tools marked **gate** require an explicit authorized-target declaration (domain / URL / target). They emit text you review and run yourself, inside scope.

## Index / 索引

| Tool | Category | Required inputs | Backend |
| --- | --- | --- | --- |
| `analyze_target` | orchestration | `target` | none |
| `assets` | source | `root` | none |
| `map` | source | `root` | none |
| `scan` | source | `root`(+`brief`) | none |
| `osint` | source | `root` | none |
| `report` | source | `root`(+`brief`) | none |
| `diff` | source | `base`,`head` | none |
| `secrets` | source | `root` | none |
| `explain` | explanation | `rule_id`(+`lang`) | none |
| `bin_info` | reverse | `path` | binutils |
| `bin_symbols` | reverse | `path` | binutils |
| `bin_strings` | reverse | `path` | binutils |
| `bin_disasm` | reverse | `path`(+`symbol`) | binutils |
| `bin_decompile` | reverse | `path`(+`symbol`) | IDA or Ghidra |
| `bin_dossier` | reverse | `path`,`symbol` | binutils / IDA / Ghidra |
| `reconstruct` | reverse | `path`(+`symbol`) | IDA / Ghidra |
| `pwn_checksec` | pwn | `path` | none |
| `pwn_gadgets` | pwn | `path`(+`filter`,`maxLen`) | binutils |
| `pwn_template` | pwn (gate) | `path`,`target` | none |
| `pwn_cyclic` | pwn | `length` / `find` | none |
| `pwn_gdbscript` | pwn | `path`(+`breakpoints`) | none |
| `pwn_libc` | pwn | `path` | binutils/none |
| `web_recon` | web (gate) | `domain` | none |
| `har_analyze` | web | `path` | none |
| `web_poc` | web (gate) | `url`,`kind` | none |
| `mobile_unpack` | mobile | `path` | none |
| `wxapkg_unpack` | mobile | `path` | none |
| `dex_decompile` | mobile | `path`(+`className`) | jadx |
| `fw_scan` | firmware | `path` | none |
| `fw_extract` | firmware | `path` | WSL/squashfs-tools |
| `js_deobfuscate` | js | `path` / `code` | none |
| `asar_unpack` | electron | `path`(+`outDir`) | none |
| `dotnet_decompile` | dotnet | `path`(+`typeName`) | ilspycmd |
| `frida_script` | dynamic (gate) | `target`,`kind` | none |
| `impact_proof` | proof (gate) | `vuln_class`(+`target`) | none |

## Orchestration

### `analyze_target`
**EN** Identify a local path or an authorized domain, then return the recommended tool chain. Routing only — nothing is analyzed by this call.
**中文** 一站式入口:丢一个本地路径(目录/ELF/PE/.NET/Mach-O/APK/IPA/小程序/DEX/固件/JS/HAR)或一个域名,识别类型并返回推荐的有序工具链(带 `tool`、`why`、`step`)。只做识别与路由,实际分析由被推荐的工具完成。

## Source / project analysis

### `assets`
**EN** List domains/URLs/IPs with `file:line` evidence. Static only; no liveness checks.
**中文** 列出目标本地代码中的资产(域名/URL/IP 等)及文件行号证据。只读静态分析,不验证存活。

### `map`
**EN** Build a code graph: files, functions, routes, imports, calls, and static dataflow candidates. Never executes code.
**中文** 生成代码图:文件、函数、路由、导入、调用关系与数据流候选(静态推断)。只读,不执行代码。

### `scan`
**EN** Full static analysis: assets, code graph, rule hits, source→sink dataflow candidates, passive artifact observations. All candidates are `inferred`, not verified vulnerabilities.
**中文** 完整静态分析:资产、代码图、规则命中、source→sink 数据流候选、被动结果观察。可选 `brief` 限定范围/漏洞类型/最低置信度并强制红线。

### `osint`
**EN** Local OSINT: extract labelled emails/phones/social profiles/names/usernames from workspace files, redacted by default, evidence preserved. No network, no identity correlation.
**中文** 本地 OSINT:从作业夹文件中提取标注过的邮箱/电话/社交资料/姓名/用户名,默认脱敏,保留文件证据。不访问网络、不做身份反查或账号关联。

### `report`
**EN** Run the full analysis and save an immutable snapshot under `.verdex/runs`: `analysis.json`, `findings.json`, redacted `osint.json`, `report.md`, self-contained `report.html`, and `report.sarif`.
**中文** 跑完整分析并在 `.verdex/runs` 下保存一份不可变快照(JSON + Markdown + 自包含 HTML 看板 + SARIF 2.1.0),返回各文件路径。

### `diff`
**EN** Compare two run snapshots by evidence fingerprint: new / fixed / still present, with severity stats.
**中文** 对比两次扫描快照,按证据指纹分出新增 / 已修复 / 仍存在,带严重度统计。

### `secrets`
**EN** Scan hardcoded secrets by provider signature (AWS/GitHub/Google/Slack/Stripe/private keys/JWT), named key constants, signing salts, and entropy. Values are redacted by default (prefix/suffix + `value_sha256` + `file:line`). Every finding is triaged as `direct` (server-side credential, report-ready) or `conditional` (client key/salt whose impact depends on server behavior; needs authorized dynamic proof).
**中文** 扫描硬编码密钥:服务商特征、命名密钥常量、签名盐、高熵启发式识别;**默认脱敏**;按可证影响分级 `direct` / `conditional`,并给出 `report_ready` / `needs_dynamic_proof` 分组。只读本地,不联网、不验证凭据。

### `explain`
**EN** Turn a rule id / vulnerability kind / CWE into plain language: what it is, why it matters, what to do — plus a technical detail block for reviewers. Bilingual (`lang: zh|en`).
**中文** 把规则 id / 漏洞类 / CWE 翻译成大白话(这是什么 / 为什么要紧 / 该怎么办),并附技术细节与复核清单,支持中英双语。

## Reverse engineering

All reverse tools are static: they parse and disassemble a local file, **never execute it**.

### `bin_info` · `bin_symbols` · `bin_strings` · `bin_disasm`
**EN** File type/arch/headers/sections; symbols and dynamic imports/exports; strings with offsets; objdump disassembly (optionally one symbol).
**中文** 文件类型/架构/头/段;符号与动态导入导出;带偏移字符串;objdump 反汇编(可指定符号)。基于本机 binutils。

### `bin_decompile`
**EN** Decompile pseudo-C with a dual backend: IDA/Hex-Rays first (`VERDEX_IDA`), automatic Ghidra fallback (`VERDEX_GHIDRA`). Optionally decompile a single `symbol`. Target is copied to a temp dir, analyzed headless, then cleaned up.
**中文** 反编译伪 C。双后端:优先 IDA/Hex-Rays,未找到时自动回退 Ghidra;可选 `symbol` 只反编译单函数。全程只分析,不执行目标。

### `bin_dossier`
**EN** One-function structured dossier: disassembly + `calls_out` + `string_xrefs` + pseudo-C when a backend is installed.
**中文** 单函数结构化档案:反汇编 + 调用的函数 + 引用的字符串 + 伪 C(装了 IDA/Ghidra 时)。

### `reconstruct`
**EN** Package pseudo-C + symbols + strings + a structured reconstruction brief for the calling model to rename, retype, annotate, and restore readable source. Verdex does not call an LLM and does not execute the target.
**中文** 源码重建:打包伪 C、符号、字符串与结构化重建指令,交由调用方模型完成重命名/补类型/注释。工具本身不调用 LLM、不联网、不执行目标。

## Pwn assist (authorized labs / CTF only)

These tools read a local binary or generate text. **Verdex never connects to a target, never sends a payload, never runs your exploit.** You review and execute inside an authorized scope.

### `pwn_checksec`
**EN** Static mitigation check: ELF (NX/Canary/PIE/RELRO/Fortify) and PE (DEP/ASLR/HighEntropy/CFG/SEH).
**中文** 静态读出缓解措施。ELF:NX/Canary/PIE/RELRO/Fortify;PE:DEP/ASLR/HighEntropy/CFG/SEH。

### `pwn_gadgets`
**EN** Search disassembly for ROP gadgets ending in `ret`; optional `filter` and `maxLen`.
**中文** 从反汇编里搜 ROP gadget,可选 `filter`(如 `pop rdi`)与 `maxLen`。

### `pwn_template` — gate
**EN** Generate a pwntools exploit scaffold as text. `target` is required and becomes the authorization banner (`local` or `host:port`). Verdex never runs or connects.
**中文** 生成 pwntools exploit 脚手架(仅文本)。`target` 必填=授权声明;脚本顶部写授权 banner。只产出脚本,不代为运行/连接。

### `pwn_cyclic`
**EN** De Bruijn pattern generation and offset lookup. Pure computation.
**中文** De Bruijn 循环模式生成 / 偏移反查(纯计算)。

### `pwn_gdbscript`
**EN** Generate a gdb/pwndbg analysis script skeleton (breakpoints, stack/memory, offset solving). Text only; you run `gdb -x` yourself.
**中文** 生成 gdb/pwndbg 动态分析脚本骨架(仅文本),由你在授权环境 `gdb -x` 运行。

### `pwn_libc`
**EN** Extract libc offsets: common symbols (`system`/`execve`/hooks/`environ`…), `/bin/sh`, libc version. Static ELF read; stripped dumps get a libc-database hint.
**中文** 从 libc.so 提取 symbol 偏移、`/bin/sh` 偏移与 libc 版本;无符号表时提示按版本比对 libc-database。

## Web assist (text only)

### `web_recon` — gate
**EN** Generate a staged recon playbook for an **authorized domain**: passive (subdomains/CT/Wayback), light-active (httpx probe), active (ffuf/nuclei, marked in-scope + rate-limited). Verdex sends no requests; commands are yours to review and run.
**中文** 为声明授权的域名生成分阶段侦察剧本(被动 / 轻主动 / 主动),标注 scope 与限速。Verdex 不发任何请求;顶部 banner 写明仅授权域、被动优先、主域授权≠子域全授权。

### `har_analyze`
**EN** Statically analyze a HAR you captured: missing security headers, insecure cookies, wildcard CORS, reflected parameters, token leakage in URLs, cleartext traffic.
**中文** 静态分析你抓的 HAR:缺失安全头、不安全 Cookie、CORS 任意源、反射参数、URL 泄露令牌、明文传输。

### `web_poc` — gate
**EN** Generate validation request templates (curl + python) for sqli/xss/ssrf/path/redirect. `url` is required and written into the authorization banner. Text only; you send it.
**中文** 生成 web 漏洞验证请求模板(curl + python,仅文本)。`url` 必填=授权声明,写进授权 banner;Verdex 不代为发送。

## Mobile

### `mobile_unpack`
**EN** Unpack APK/IPA/AAB/JAR and inventory contents; decode binary AndroidManifest (pure Node AXML) into attack surface: package, permissions, exported components, debuggable, allowBackup, cleartext, network security config. Extracts native libs ready for `bin_decompile`.
**中文** 解包 ZIP 容器并清点内容;纯 Node 解码二进制 AndroidManifest,输出包名/权限/导出组件/debuggable 等攻击面;抽出原生库供 `bin_decompile`。

### `wxapkg_unpack`
**EN** Unpack WeChat mini-program `.wxapkg` (custom binary format, pure Node, path-traversal safe); inventory js/wxml/wxss/json.
**中文** 解包微信小程序 `.wxapkg`(纯 Node 解析,防路径穿越),清点 js/wxml/wxss/json。

### `dex_decompile`
**EN** Decompile APK/DEX to Java via jadx; inventory packages/classes; optionally return one class. If jadx fails on a method, recover Kotlin `@DebugMetadata`/`@Metadata` annotations as a fallback.
**中文** 用 jadx 反编译成 Java;清点 package/class,可选 `className`;反编译失败时从 Kotlin 注解恢复局部变量名、行号等线索。

## Firmware (pure static)

### `fw_scan`
**EN** Mini-binwalk: locate embedded filesystems (SquashFS/CramFS/JFFS2/UBI), compressed blocks, boot headers, ELF/PEM signatures with offsets, plus an entropy map.
**中文** 固件分流:扫描内嵌文件系统/压缩块/引导头/ELF/PEM 特征与偏移,给熵分布图标出加密/压缩区段。

### `fw_extract`
**EN** Extract SquashFS images (Windows via WSL `unsquashfs`, Linux native) and inventory the rootfs: ELF, configs, scripts, credential files.
**中文** 解包 SquashFS(Windows 经 WSL),清点 rootfs——原生 ELF、配置、脚本、凭据文件。

## JS / Electron / .NET

### `js_deobfuscate`
**EN** Pure static JS deobfuscation: decode `\xHH`/`\uHHHH` escapes, beautify minified code, flag obfuscation patterns, extract URLs/IPs/base64. Never executes the script.
**中文** JS 反混淆辅助(纯静态,绝不执行):解转义、美化、识别混淆特征、提取 URL/IP/base64。

### `asar_unpack`
**EN** Unpack Electron `.asar` archives (pure Node, path-traversal safe), inventory js/json/html/css/.node; route JS to `js_deobfuscate`, native addons to `bin_decompile`.
**中文** 解包 Electron `.asar`(纯 Node,防路径穿越),清点内容并可路由到 JS 反混淆 / 原生反编译。

### `dotnet_decompile`
**EN** Decompile .NET/CLR assemblies to C# via ILSpy (`ilspycmd`, read-only, never executes). Optional `typeName` focuses one type.
**中文** .NET/CLR 程序集反编译成 C#(ILSpy 后端,只读不执行);可选 `typeName` 聚焦某类型。

## Dynamic assist / impact proof (text only)

### `frida_script` — gate
**EN** Generate a Frida script (`unpack` / `hook` / `crypto` / `network`) for an **authorized target**. Verdex never attaches, injects, or runs; you run `frida -U -f <target> -l x.js` yourself.
**中文** 为声明授权的目标生成 Frida 脚本(脱壳/ hook / 抓密钥 / 抓网络)。Verdex 从不 attach/注入/运行,由你在自己授权的设备上执行。

### `impact_proof` — gate
**EN** Turn a conditional finding (signing salt, IDOR, hardcoded credential, SSRF, SQLi, auth bypass, open redirect, XSS, JWT) into a minimal, data-safe, stop-at-first-proof validation plan: why static alone gets rejected, the smallest proof, data-safety laws, evidence checklist, report framing, stop point. Text only; you run it.
**中文** 把"条件性理论风险"升级成"审核可复核的已证影响"的验证方案:为何被驳回、最小影响步骤、数据安全铁律、取证清单、报告写法、点到为止的停止点。Verdex 只产方案,不发请求。

## Safety contract

- No tool performs a network request or executes a target. Tests assert `openWorldHint:false` and `destructiveHint:false` for the full tool surface.
- Gate tools reject missing/blank authorized-target declarations.
- `brief` enforces scope, vuln classes, minimum confidence, and `no-payload / no-bruteforce / no-out-of-scope`; attempts to loosen red lines are rejected.
- Static findings are `inferred` candidates for human review — not verified vulnerabilities. Never report them as confirmed without reproducing in an authorized environment.
