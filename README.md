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

一站式入口：`analyze_target`——丢一个路径(目录或文件),自动识别类型(目录/ELF/PE/**.NET**/Mach-O/APK/IPA/小程序/DEX/固件 SquashFS·JFFS2·UBI/JS/HAR)并返回推荐的有序工具链。只做识别与路由,实际分析由被推荐的工具完成。

`dotnet_decompile`：.NET/CLR 程序集(.dll/.exe)反编译成 **C#**(ILSpy/ilspycmd 后端,只读不执行)。可选 `typeName` 聚焦某类型。需装 ilspycmd(`VERDEX_ILSPY` 指向 `ilspycmd.dll`)+ 对应 .NET runtime。C#/VB/F# 托管程序集通吃。

`asar_unpack`：解包 Electron `.asar` 归档(纯 Node,防路径穿越,只读):提取并清点 js/json/html/css/.node,js 可路由 `js_deobfuscate`、`.node` 原生插件可 `bin_decompile`。桌面 Electron 应用逆向入口。

`bin_dossier`:单函数结构化档案(对标 REA function dossier)——给一个 `symbol`,产出它的反汇编 + 调用的函数(`calls_out`)+ 引用的字符串(`string_xrefs`)+ 伪 C(装了 IDA/Ghidra 时)。快速看懂一个函数在干什么。

源码分析工具：`assets`、`map`、`scan`、`osint`、`report`（跑完整分析并在 `.verdex/runs` 存一份不可变快照:JSON + Markdown + HTML + SARIF 报告,返回各文件路径）。

- `secrets`：扫描硬编码密钥——按服务商特征(AWS/GitHub/Google/Slack/Stripe/私钥/JWT 等)、**命名密钥常量**(`*_APP_KEY`/`*_SECRET`/`CLIENT_ID` 等按变量名判定)、**签名盐**(`appSecret=`/`&key=`)+ 高熵启发式识别,**默认脱敏**(只给前后几位 + value_sha256 + 文件行号,绝不输出密钥原文)。只读本地,不联网、不验证凭据。
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

- `frida_script`：生成 Frida 动态分析脚本(**仅文本,Verdex 不 attach / 不注入 / 不运行**)。`target` 必填=授权目标声明(包名/进程)。`kind`:`unpack`(脱壳 dump 内存 dex——拿加壳 App 的业务代码)、`hook`(hook 指定 `className.method` 抓参数/返回)、`crypto`(抓运行时 key/IV/明文/算法)、`network`(抓 okhttp URL/headers 看签名怎么拼)。由你审阅后在**自己授权的设备/App** 上 `frida -U -f <target> -l x.js` 运行。

> 动态分析的三道闸:① `target` 是**必填的授权目标声明**;② Verdex **只产脚本文本**,从不 attach/注入/运行;③ **人在环路**——模型提议、你审阅批准并亲自运行。静态够不着的(脱壳、运行时密钥、真实请求参数)在**你拥有或被授权的目标**上用动态补齐。`pwn_cyclic` 纯计算、`pwn_gdbscript`/`frida_script` 只生成脚本文本——执行都由你在授权环境完成。

移动端工具（只读解包,不执行包内代码;仅限你拥有或被授权的 app）：
- `mobile_unpack`：解包 APK/IPA/AAB/JAR(ZIP 容器)并清点内容,把原生库(`.so`/`.dylib`/Mach-O)、DEX、JS、小程序包、manifest 分类,并抽出原生库到可直接喂给 `bin_decompile` 的路径。**自动解码二进制 AndroidManifest**(纯 Node AXML 解析)输出攻击面:包名/版本/权限列表/导出组件/debuggable/allowBackup/cleartext/网络安全配置。
- 原生库(ELF/Mach-O ARM)现可直接经 `bin_decompile`(IDA/Ghidra)反编译——`detectFormat` 已支持 Mach-O(thin/fat、32/64 位),解锁 iOS/macOS 原生二进制。
- `wxapkg_unpack`：解包微信小程序 `.wxapkg` 包(自定义二进制格式,纯 Node 解析,防路径穿越),提取并清点 js/wxml/wxss/json;JS 可路由到 `scan` 分析逻辑。
- `dex_decompile`：用 jadx 把 APK/DEX 反编译成 **Java**(只读,不运行 app)。清点 package/class,可选 `className` 返回指定类的 Java 源码。需装 jadx(设 `VERDEX_JADX` 指向 `bin/jadx`,或放在常见路径),jadx 需 JDK 11+(你的 JDK 21 够)。**反编译失败("Method not decompiled")时自动从 Kotlin `@DebugMetadata`/`@Metadata` 注解恢复**:局部变量名、挂起点行号、类成员名——即使方法体没还原,也能推断逻辑结构。
- `js_deobfuscate`：JS 反混淆辅助(**纯静态,绝不执行脚本**)。解 `\xHH`/`\uHHHH` 转义揪出藏的 URL/字符串、把压缩成一行的代码美化成可读、识别混淆特征(`_0x` 标识符 / Dean Edwards packer / eval / atob / 大字符串数组)、提取 URL/IP/base64。字符串数组等运行时解码需执行才现形,本工具不做(越红线)。

物联网固件工具（纯静态,只读,不解包不执行;仅限你拥有或被授权的设备）：
- `fw_scan`：固件镜像分流(mini-binwalk)。扫描内嵌文件系统(SquashFS/CramFS/JFFS2/UBI)、压缩块(gzip/xz/lzma/bzip2/lzo)、引导头(U-Boot/TRX/DTB/Android boot/cpio)、ELF、PEM 的特征与**偏移**,每个命中附建议解包工具;并给**熵分布图**标出加密/压缩区段(整体高熵且无特征→可能是加密固件)。
- `fw_extract`：解包 **SquashFS** 固件镜像(Windows 下经 WSL 调 `unsquashfs`,Linux 原生)并清点 rootfs——原生 ELF(抽出可喂 `bin_decompile`)、配置、脚本、凭据文件(passwd/密钥等)。需 WSL 里装 `squashfs-tools`(可设 `VERDEX_WSL_DISTRO` 指定发行版)。
- 解包后得到 rootfs:ELF→`bin_decompile`、配置/脚本→`scan`、硬编码凭据→`secrets`,直接复用现有能力。其他文件系统(JFFS2/UBI)先用 `fw_scan` 定位,再用对应工具(jefferson/ubireader)。

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
