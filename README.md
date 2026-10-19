# Verdex Workbench
[![M8ven Score](https://m8ven.ai/badge/mcp/yilanchia-verdex-1s28o0?v=8acf7584845a7b298157c8c27d0f28fc)](https://m8ven.ai/mcp/yilanchia-verdex-1s28o0?s=readme)

Verdex 是一个**证据优先**的本地安全研究工作台:源码审计、逆向、pwn 与 web 攻防辅助,并通过 MCP 让大模型(如 DeepSeek、Claude Code)自主编排这些能力。

> **负责任使用**:Verdex 全程**只读分析 / 只生成文本**,不执行目标、不发起网络请求、不自主攻击。pwn/web 的脚手架工具需显式声明授权目标,仅限 CTF、你自建的实验室、或你拥有/被明确授权的系统。禁止用于未授权目标。

核心是一个可验证的本地分析内核：

- 资产清单保留文件、行号和原文片段，不把字符串猜测当成事实。
- 代码图记录文件、函数、路由、导入和调用关系。
- 数据流分析寻找请求输入到危险操作的候选路径，并明确标记为静态推断。
- 发现使用确定性证据指纹去重，保留来源和证据链。
- brief 强制执行范围、漏洞类型、最低置信度和禁止越界/爆破/载荷红线。
- 被动归档支持 Nuclei 风格 JSONL、常见 JSON 结果和基础 SARIF，不把外部结果升级为已验证漏洞。
- 本地 OSINT 提取显式邮箱、电话、社交资料链接、姓名字段和用户名字段，默认脱敏并保留文件证据。
- 分析输出带 schema、覆盖统计和限制项，方便后续接入代理、AST 引擎和运行时证据。

当前内核只读取本地作业夹，不发起网络请求，不生成利用代码或攻击步骤。

## 使用

```powershell
npm test
npm start
node src/cli.js assets D:\path\to\target
node src/cli.js map D:\path\to\target
node src/cli.js osint D:\path\to\target
node src/cli.js scan D:\path\to\target
node src/cli.js scan D:\path\to\target D:\path\to\brief.json
node src/cli.js report D:\path\to\target D:\path\to\output D:\path\to\brief.json
node src/cli.js mcp
```

## MCP server(让大模型主导分析）

`node src/cli.js mcp` 启动一个零依赖的本地 MCP server（JSON-RPC 2.0 over stdio），把只读分析能力暴露为工具。全部只读、不访问网络、不生成载荷或攻击步骤；`scan` 的可选 brief 仍走 `validateBrief` 强制范围与红线。

源码分析工具：`assets`、`map`、`scan`、`osint`、`report`（跑完整分析并在 `.verdex/runs` 存一份不可变快照:JSON + Markdown + HTML 报告,返回各文件路径）。

- `diff`：对比两次扫描快照(`.verdex/runs` 下的 run 目录),按证据指纹分出**新增 / 已修复 / 仍存在**的候选,带严重度统计——追踪"改了什么、修了什么、还剩什么"。只读。

Web 攻防工具（只读分析 / 只产文本,Verdex 不发起任何请求）：
- `har_analyze`：静态分析你抓的 HAR 流量(Burp/DevTools 导出)——缺失安全头、不安全 Cookie、CORS 任意源、反射参数(XSS 候选)、URL 泄露令牌、明文传输。
- `web_poc`：生成 web 漏洞验证请求模板(curl + python,仅文本)。`url` 必填=显式声明授权目标,写进授权 banner;`kind` 支持 sqli/xss/ssrf/path/redirect。Verdex 不代为发送,由你审阅后在授权范围自行运行。禁止用于未授权系统。

二进制逆向工具（证据分层，只静态解析、**绝不执行目标文件**）：

- `bin_info`（文件类型/架构/头/段）、`bin_symbols`（符号与动态导入导出）、`bin_strings`（带偏移字符串）、`bin_disasm`（objdump 反汇编，可指定符号）。基于本机 binutils（objdump/nm/strings/file）。
- `bin_decompile`（反编译出伪 C，可选 `symbol` 只反编译单函数）。**双后端**:优先 IDA Pro / Hex-Rays(设 `VERDEX_IDA` 指向 `idat.exe`),未找到 IDA 时自动回退到 **Ghidra**(免费,设 `VERDEX_GHIDRA` 指向 `support/analyzeHeadless`,需 JDK 21+)。两者都把目标拷到临时目录、headless 运行、读回结果后清理,全程只分析不执行目标。IDA 不在也能用,对开源用户友好。

- `reconstruct`（源码重建）：打包伪 C（IDA）+ 符号 + 字符串 + 一份结构化**重建指令**（`reconstruction_brief`，编码四项侧重:忠实不幻觉、可读性、结构恢复、调用关系），交由调用方模型（如 DeepSeek）重命名、补类型、加注释、译回接近原始风格的可读源码。可选 `symbol` 只重建单函数。

反编译伪 C 是对二进制的**重建推断**，不是无损还原原始源码——注释、宏、局部变量名在编译后已永久丢失。`reconstruct` 工具本身**不调用 LLM、不访问网络、不执行目标**:它只准备证据和指令,真正的重建由驱动它的模型在回复中完成。

### 利用辅助工具（仅限授权靶场）

以下工具用于在 **你拥有或被明确授权的目标**（CTF、自建实验室）上辅助 exploit 开发。它们**全部只读分析本地二进制 / 只生成文本**——Verdex 代码里没有联网、发包或执行攻击的能力,利用动作由使用者自行完成。禁止用于未授权系统。

- `pwn_checksec`：静态读出缓解措施。ELF:NX/Canary/PIE/RELRO/Fortify;PE:DEP/ASLR/HighEntropy/CFG/SEH。
- `pwn_gadgets`：从反汇编里搜 ROP gadget（以 `ret` 结尾的短序列），可选 `filter`（如 `pop rdi`）和 `maxLen`。
- `pwn_template`：生成 pwntools exploit 脚手架（**仅文本**）。`target` 必填,显式声明授权目标（`local` 或 `host:port`）,会写进脚本顶部的授权 banner。Verdex 只产出脚本,**不代为运行、不代为连接**;审阅并确认授权后由你自己执行。
- `pwn_cyclic`：De Bruijn 循环模式生成 / 偏移反查（纯计算,不涉及二进制或执行）。求栈溢出偏移的标准手法:生成模式→喂给你自己运行的目标→用崩溃时 RSP/EIP 的值反查偏移。
- `pwn_gdbscript`：生成 gdb/pwndbg 动态分析脚本（**仅文本**:断点、看栈/内存、求偏移的命令骨架）。由你在自己授权环境里 `gdb -x 脚本 ./bin` 运行;Verdex 不执行目标、不连接任何系统。
- `pwn_libc`：从 libc.so 提取 exploit 所需偏移——常用符号(system/execve/puts/__free_hook/__malloc_hook/__libc_start_main/environ…)、`/bin/sh` 字符串偏移、libc 版本。纯静态读 ELF,只读不执行;堆题/ret2libc 必备。无符号表(内存 dump/strip)时给出按版本比对 libc-database 的提示。

> 动态逆向辅助的边界:Verdex 自身**从不执行目标二进制**。`pwn_cyclic` 是纯计算,`pwn_gdbscript` 只生成脚本文本——真正的调试与运行由你在自己的授权环境中完成。

接入 DeepSeek Harness（dsh）：在 profile 的 `cordis.yml` 里加一个 MCP 客户端实例，大模型即可以 `mcp__verdex__scan` 等名字调用：

```yaml
- id: mcp-verdex
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: verdex
    transport: stdio
    command: node
    args: ['/path/to/verdex/src/cli.js', 'mcp']
```

同样的 server 也可被 Claude Code、Codex 等 MCP 客户端复用。

### 在 dsh 里挂载（已验证）

仓库根目录的 `verdex-mcp.patch.yml` 是一个 dsh 补丁文件（用 `insert` 语法把 Verdex 挂进插件树）。两种用法：

- 一次性试用（不改动你的 dsh 配置）：

  ```powershell
  dsh web --patch /path/to/verdex-mcp.patch.yml
  ```

- 永久挂载：把 `verdex-mcp.patch.yml` 里的 `- insert:` 块追加到 `~/.dsh/profiles/web/cordis.patch.yml`（放在 `dsh-skin managed` 受管区块**之外**，别碰那段）。

挂载后，模型会看到 `mcp__verdex__scan`、`mcp__verdex__bin_decompile`、`mcp__verdex__bin_disasm` 等工具。可用 `dsh web --patch ... --dump-config` 确认条目已合成进配置树。

运行 `npm start` 后访问 `http://127.0.0.1:3210`。前端是本地零依赖工作台：可以选择工作目录、手动补充域名/URL/IP 资产、填写 brief，查看覆盖、资产面、脱敏 OSINT 观察及待复核候选。服务只监听本机地址，分析接口不会主动发起网络请求。

分析完成后可以点击“保存快照”。工作台会在 `.verdex/runs` 中保存不可变的 `analysis.json`、`findings.json`、脱敏 `osint.json`、Markdown 报告（`report.md`，含执行摘要/严重度统计）、一份自包含的 **HTML 报告**（`report.html`，内联样式、严重度看板、证据链、修复方向），以及一份 **SARIF 2.1.0**（`report.sarif`）——可直接上传到 GitHub 代码扫描、在 PR 里标注,或用 VS Code 的 SARIF 查看器打开。总览页的“运行记录”可以查看历史摘要并下载报告。

“个人查找”是独立功能：输入已知邮箱、手机号、用户名、姓名或资料链接后，只在当前工作目录中做精确文本匹配，结果默认脱敏并保留文件和行号证据。它不会访问互联网、做身份推断或账号关联。

“AI 设置”支持 OpenAI-compatible 和本地模型端点。AI 默认关闭，只有明确开启网络请求并点击“复核当前候选”才会发送有限的候选证据；远程端点必须使用 HTTPS，本地模型可使用 `http://127.0.0.1`。API Key 仅保存在当前服务进程内存，不写入 `.verdex/ai-settings.json`，服务重启后需要重新输入。

`scan` 输出一份 JSON 分析结果，包含资产、代码图、静态规则命中、数据流候选和被动结果观察。候选必须回到原文件核对后，才能进入人工复核清单。

`report` 会在输出目录建立一次不可变运行快照，写入 `analysis.json`、`findings.json`、脱敏策略下的 `osint.json` 和 `report.md`。brief 的最小格式：

```json
{
  "schema": "VerdexBrief/v1",
  "scope": {
    "include": ["*.example.com"],
    "exclude": ["dev.example.com"]
  },
  "vuln_classes": ["sql", "ssrf", "xss"],
  "min_confidence": "medium",
  "redlines": ["no-payload", "no-bruteforce", "no-out-of-scope"],
  "allow": ["read_workspace", "parse_artifacts"]
}
```

brief 缺失 `include`、包含危险授权，或试图降低强制红线时会直接拒绝。`vuln_classes` 支持 `sqli`、`rce`、`path-traversal` 等常用别名。

OSINT 默认只读取本地作业夹，不访问网络服务，不做姓名反查、身份关联或数据经纪查询。默认输出脱敏值；可以在 brief 中限定类别：

```json
{
  "osint": {
    "enabled": true,
    "categories": ["email", "phone", "social-profile", "person-name", "username"],
    "reveal": false
  }
}
```

## 设计方向

工程采用四层证据模型：资产证据、静态关系、数据流候选、人工结论。每层保留 authority、epistemic state、confidence、coverage 和 limitations，后续接入 AST、Semgrep、浏览器被动观测或其他分析器时，不会把推断结果伪装成运行时事实。
