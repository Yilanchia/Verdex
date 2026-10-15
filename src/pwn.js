import fs from "node:fs";
import path from "node:path";
import { resolveBinary, run, clip } from "./reverse.js";

// Read-only pwn/exploit-development ASSISTANCE. These tools inspect a local
// binary (protections, ROP gadgets) to help a human develop an exploit for an
// AUTHORIZED target (CTF / own lab). They NEVER connect to, send payloads to,
// or execute anything against a target. Verdex has no network/attack capability
// by construction — the human runs any exploit themselves.

const MAX_GADGETS = 400;

function detectFormat(file) {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(4);
    fs.readSync(fd, buf, 0, 4, 0);
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "elf";
    if (buf[0] === 0x4d && buf[1] === 0x5a) return "pe";
    return "unknown";
  } finally {
    fs.closeSync(fd);
  }
}

function envelope(tool, file, format, body) {
  return {
    schema: "VerdexPwn/v1",
    tool,
    file: path.basename(file),
    format,
    authority: "local-binary-static",
    epistemic: "fact",
    ...body,
    limitations: [
      "只读分析本地二进制:不连接目标、不发送载荷、不执行任何攻击动作。",
      "利用由使用者在授权范围(CTF/自建实验室)内自行完成;本工具不具备联网或攻击能力。",
    ],
  };
}

async function checksecElf(file) {
  const [headers, dynamic, symbols] = await Promise.all([
    run("readelf", ["-lW", file]).catch((e) => `# readelf -l: ${e.message}`),
    run("readelf", ["-dW", file]).catch(() => ""),
    run("readelf", ["-sW", file]).catch(() => ""),
  ]);
  const nx = !/GNU_STACK\b[^\n]*\bRWE\b/.test(headers) && /GNU_STACK/.test(headers);
  const hasRelro = /GNU_RELRO/.test(headers);
  const bindNow = /\bBIND_NOW\b/.test(dynamic) || /\bFLAGS\b[^\n]*\bNOW\b/.test(dynamic) || /\(FLAGS_1\)[^\n]*NOW/.test(dynamic);
  const relro = hasRelro ? (bindNow ? "full" : "partial") : "none";
  const canary = /__stack_chk_fail|__stack_chk_guard/.test(symbols);
  const pie = /\bType:\s+DYN\b/.test(headers) || /Position-Independent/.test(headers);
  const fortify = /__\w+_chk\b/.test(symbols);
  return {
    nx: { enabled: nx, note: "栈不可执行(No-eXecute)" },
    canary: { enabled: canary, note: "栈溢出 canary 保护" },
    pie: { enabled: pie, note: "位置无关可执行(地址随机化基础)" },
    relro: { level: relro, note: "GOT 保护:none/partial/full" },
    fortify: { enabled: fortify, note: "_FORTIFY_SOURCE 加固函数" },
  };
}

async function checksecPe(file) {
  // DLL characteristics flags from the PE optional header (via objdump -p).
  const dump = await run("objdump", ["-p", file]).catch((e) => `# objdump -p: ${e.message}`);
  const flagsHex = (dump.match(/DllCharacteristics\s+(?:0x)?([0-9a-fA-F]+)/i) || [])[1];
  const flags = flagsHex ? parseInt(flagsHex, 16) : null;
  const has = (bit) => (flags === null ? null : Boolean(flags & bit));
  return {
    aslr: { enabled: has(0x0040), note: "DYNAMIC_BASE:地址随机化" },
    high_entropy_aslr: { enabled: has(0x0020), note: "HIGH_ENTROPY_VA:64 位高熵 ASLR" },
    dep: { enabled: has(0x0100), note: "NX_COMPAT:数据执行保护(DEP)" },
    seh: { enabled: has(0x0400) === null ? null : !has(0x0400), note: "是否启用 SEH(NO_SEH 位取反)" },
    cfg: { enabled: has(0x4000), note: "GUARD_CF:控制流防护(CFG)" },
    force_integrity: { enabled: has(0x0080), note: "强制签名校验" },
    ...(flags === null ? { parse_note: "未能从 objdump -p 解析到 DllCharacteristics" } : { dll_characteristics: `0x${flags.toString(16)}` }),
  };
}

export async function pwnChecksec(value) {
  const file = resolveBinary(value);
  const format = detectFormat(file);
  if (format === "elf") return envelope("pwn_checksec", file, "elf", { protections: await checksecElf(file), backend: "readelf" });
  if (format === "pe") return envelope("pwn_checksec", file, "pe", { protections: await checksecPe(file), backend: "objdump" });
  throw new Error("不支持的二进制格式(仅 ELF/PE);magic 既非 \\x7fELF 也非 MZ");
}

// Lightweight ROP gadget finder: scans objdump disassembly for short
// instruction runs ending in a return. Not a full ropper, but enough for
// locating common gadgets (pop rdi; ret, etc.) during CTF exploit dev.
export async function pwnGadgets(value, options = {}) {
  const file = resolveBinary(value);
  const format = detectFormat(file);
  if (format !== "elf" && format !== "pe") throw new Error("不支持的二进制格式(仅 ELF/PE)");
  const maxLen = Number.isInteger(options.maxLen) && options.maxLen >= 1 && options.maxLen <= 6 ? options.maxLen : 4;
  const filter = typeof options.filter === "string" ? options.filter.toLowerCase().trim() : "";
  const stdout = await run("objdump", ["-d", "-M", "intel", "--no-show-raw-insn", file]);

  const insns = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^\s*([0-9a-f]+):\s+(.+?)\s*$/i);
    if (m) insns.push({ addr: m[1], text: m[2].replace(/\s+/g, " ").trim() });
  }
  const isRet = (t) => /^(ret|retn|retf)\b/.test(t) || /^repz? ret/.test(t);
  const seen = new Set();
  const gadgets = [];
  for (let i = 0; i < insns.length && gadgets.length < MAX_GADGETS; i++) {
    if (!isRet(insns[i].text)) continue;
    for (let len = 1; len <= maxLen && i - len + 1 >= 0; len++) {
      const seq = insns.slice(i - len + 1, i + 1);
      // Don't let a gadget span across another ret in the middle.
      if (seq.slice(0, -1).some((x) => isRet(x.text))) break;
      const repr = seq.map((x) => x.text).join(" ; ");
      if (filter && !repr.toLowerCase().includes(filter)) continue;
      if (seen.has(repr)) continue;
      seen.add(repr);
      gadgets.push({ addr: `0x${seq[0].addr}`, gadget: repr });
      if (gadgets.length >= MAX_GADGETS) break;
    }
  }
  return envelope("pwn_gadgets", file, format, {
    backend: "objdump",
    max_len: maxLen,
    filter: filter || null,
    gadget_count: gadgets.length,
    capped: gadgets.length >= MAX_GADGETS,
    gadgets,
  });
}

const LIBC_SYMBOLS = [
  "system", "execve", "execl", "puts", "printf", "read", "write", "open", "gets",
  "__free_hook", "__malloc_hook", "__realloc_hook", "__libc_start_main",
  "environ", "__environ", "setcontext", "mprotect",
];

// Reads a libc.so and extracts the offsets a pwn exploit needs: common symbol
// addresses + the "/bin/sh" string offset + the libc version. Pure static ELF
// read (readelf/strings) — never executes the library.
export async function pwnLibc(value) {
  const file = resolveBinary(value);
  if (detectFormat(file) !== "elf") throw new Error("pwn_libc 只支持 ELF 的 libc.so");
  const [symOut, dynOut, strOut] = await Promise.all([
    run("readelf", ["-sW", file]).catch(() => ""),
    run("readelf", ["-dW", file]).catch(() => ""),
    run("strings", ["-t", "x", file]).catch(() => ""),
  ]);

  const symbols = {};
  for (const line of (symOut + "\n" + "").split(/\r?\n/)) {
    // readelf -s columns: Num: Value Size Type Bind Vis Ndx Name
    const m = line.match(/^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+?)\s*$/i);
    if (!m) continue;
    const name = m[2].split("@")[0].trim();
    if (LIBC_SYMBOLS.includes(name) && !symbols[name]) symbols[name] = `0x${m[1].replace(/^0+(?=.)/, "")}`;
  }

  const binsh = [];
  for (const line of strOut.split(/\r?\n/)) {
    const m = line.match(/^\s*([0-9a-f]+)\s+(.*)$/i);
    if (m && /\/bin\/sh\b/.test(m[2])) binsh.push(`0x${m[1].replace(/^0+(?=.)/, "")}`);
  }

  const verMatch = strOut.match(/GNU C Library[^\n]*?release version (\d+\.\d+)/i) || strOut.match(/glibc[ -](\d+\.\d+)/i);
  const noSymbols = Object.keys(symbols).length === 0;

  return {
    schema: "VerdexPwn/v1",
    tool: "pwn_libc",
    file: path.basename(file),
    authority: "local-binary-static",
    epistemic: "fact",
    libc_version: verMatch ? verMatch[1] : null,
    symbols,
    ...(noSymbols ? { no_symbol_table: `该文件无符号表(可能是内存 dump 或已 strip)。可用 libc 版本 ${verMatch ? verMatch[1] : "?"} 去 libc-database 比对取偏移,或用带符号的发行版 libc.so。` } : {}),
    bin_sh_offsets: binsh,
    one_gadget: {
      available: false,
      note: "one_gadget 需约束求解,本工具不内置;在你的环境里运行 `one_gadget " + path.basename(file) + "` 获取,配合上面的符号偏移使用。",
    },
    limitations: [
      "只静态读取 libc 的符号表与字符串,未执行该库。",
      "偏移是文件内偏移(相对 libc 基址);运行时加上泄露的 libc 基址即为实际地址。",
      "剥离符号的 libc 可能取不到部分偏移;可用 libc 版本去 libc-database 比对。",
    ],
  };
}

async function detectArch(file) {
  const out = await run("objdump", ["-f", file]).catch(() => "");
  if (/x86-64|i386:x86-64/.test(out)) return "amd64";
  if (/i386|80386/.test(out)) return "i386";
  if (/aarch64/.test(out)) return "aarch64";
  if (/\barm\b/i.test(out)) return "arm";
  return "amd64";
}

function parseTarget(target) {
  const value = String(target || "").trim();
  if (!value) throw new Error("参数 target 必填:声明授权目标。本地题用 'local',远程题用 'host:port'(例如 chall.ctf.io:1337)");
  if (value.toLowerCase() === "local") return { kind: "local" };
  const m = value.match(/^([A-Za-z0-9_.-]+):(\d{1,5})$/);
  if (!m || Number(m[2]) > 65535) throw new Error("target 格式应为 'local' 或 'host:port'");
  return { kind: "remote", host: m[1], port: Number(m[2]) };
}

// Generates a pwntools exploit SCAFFOLD (text only). Verdex never runs it or
// connects anywhere — the human reviews and runs it against a target they are
// authorized to test (CTF / own lab). target is a required explicit
// authorization declaration, embedded into the script banner.
export async function pwnTemplate(value, options = {}) {
  const file = resolveBinary(value);
  const target = parseTarget(options.target);
  const format = detectFormat(file);
  if (format !== "elf" && format !== "pe") throw new Error("不支持的二进制格式(仅 ELF/PE)");
  const arch = await detectArch(file);
  const osName = format === "elf" ? "linux" : "windows";
  const base = path.basename(file);
  const conn = target.kind === "local"
    ? `io = process([exe.path])        # 本地题:直接起进程`
    : `io = remote(${JSON.stringify(target.host)}, ${target.port})   # 远程题:连接声明的授权目标`;
  const targetDesc = target.kind === "local" ? "local process" : `${target.host}:${target.port}`;

  const script = [
    `#!/usr/bin/env python3`,
    `# ============================================================`,
    `# Verdex 生成的 exploit 脚手架 —— 仅供授权测试(CTF / 自建实验室)。`,
    `# 授权目标: ${targetDesc}`,
    `# 使用者负责确认对该目标拥有合法授权;禁止用于未授权系统。`,
    `# Verdex 只生成此脚本,不代为运行、不代为连接。由你审阅后自行执行。`,
    `# ============================================================`,
    `from pwn import *`,
    ``,
    `context.binary = exe = ELF(${JSON.stringify(base)})`,
    `context.arch = ${JSON.stringify(arch)}`,
    `context.os = ${JSON.stringify(osName)}`,
    `context.log_level = "info"`,
    ``,
    `# 保护机制(由 pwn_checksec 探测,仅供参考):`,
    `#   见 pwn_checksec 输出,据此选择利用手法。`,
    ``,
    `def start():`,
    `    ${conn}`,
    `    return io`,
    ``,
    `io = start()`,
    ``,
    `# --- TODO: 在授权范围内填写你的利用逻辑 ---`,
    `# offset = cyclic_find(...)              # 用 pwn_gadgets / 调试确定溢出偏移`,
    `# rop = ROP(exe)`,
    `# rop.raw(rop.find_gadget(["ret"]))      # 栈对齐`,
    `# payload = flat({ offset: rop.chain() })`,
    `# io.sendline(payload)`,
    ``,
    `io.interactive()`,
    ``,
  ].join("\n");

  return {
    schema: "VerdexPwn/v1",
    tool: "pwn_template",
    file: base,
    format,
    arch,
    authority: "generated-scaffold",
    epistemic: "generated",
    authorized_target: targetDesc,
    language: "python-pwntools",
    script,
    usage: "审阅脚本,确认对目标有合法授权后,在你自己的环境里运行(例如 `python3 exp.py`)。Verdex 不会代为执行。",
    limitations: [
      "这是脚手架模板,不是完成的 exploit;利用逻辑需你在授权范围内自行填写。",
      "Verdex 只生成文本,绝不连接目标、不发送载荷、不执行脚本;运行与授权责任在使用者。",
      "仅限 CTF / 自建实验室 / 你拥有或被明确授权的目标;禁止用于未授权系统。",
    ],
  };
}

// De Bruijn cyclic pattern — pure computation, no binary involved. Used to find
// the exact overflow offset: generate a pattern, feed it to the crashing input
// (the human does that), then look up the value in RSP/EIP here.
const CYCLIC_ALPHABET = "abcdefghijklmnopqrstuvwxyz";

function deBruijn(length, n = 4) {
  const k = CYCLIC_ALPHABET.length;
  const a = new Array(k * n).fill(0);
  const seq = [];
  function db(t, p) {
    if (seq.length >= length) return;
    if (t > n) {
      if (n % p === 0) for (let j = 1; j <= p && seq.length < length; j++) seq.push(CYCLIC_ALPHABET[a[j]]);
    } else {
      a[t] = a[t - p];
      db(t + 1, p);
      for (let j = a[t - p] + 1; j < k; j++) { a[t] = j; db(t + 1, t); }
    }
  }
  db(1, 1);
  return seq.slice(0, length).join("");
}

export function pwnCyclic(options = {}) {
  const n = Number.isInteger(options.n) && options.n >= 2 && options.n <= 8 ? options.n : 4;
  if (options.lookup !== undefined && options.lookup !== null && String(options.lookup).length) {
    // Accept a substring (e.g. "faab") or a little-endian hex value from a register.
    let needle = String(options.lookup);
    const hexMatch = needle.match(/^0x([0-9a-fA-F]+)$/);
    if (hexMatch) {
      const bytes = hexMatch[1].padStart(hexMatch[1].length + (hexMatch[1].length % 2), "0").match(/../g).reverse();
      needle = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join("").replace(/[^\x20-\x7e]/g, "");
    }
    const full = deBruijn(60000, n);
    const offset = full.indexOf(needle);
    return {
      schema: "VerdexPwn/v1", tool: "pwn_cyclic", mode: "lookup", n, lookup: String(options.lookup),
      offset: offset >= 0 ? offset : null,
      note: offset >= 0 ? `控制流劫持点距离输入起始的偏移为 ${offset} 字节。` : "未在模式中找到该子串;确认 n 与生成时一致,或崩溃值并非来自该模式。",
      limitations: ["纯计算,不涉及二进制或执行。偏移需用你的崩溃现场(RSP/EIP 的值)查得。"],
    };
  }
  const length = Number.isInteger(options.length) && options.length > 0 && options.length <= 20000 ? options.length : 200;
  return {
    schema: "VerdexPwn/v1", tool: "pwn_cyclic", mode: "generate", n, length,
    pattern: deBruijn(length, n),
    usage: "把 pattern 作为溢出输入喂给(你自己运行的)目标;崩溃后用 pwn_cyclic 的 lookup 传入 RSP/EIP 的值求偏移。",
    limitations: ["纯计算,不涉及二进制或执行。"],
  };
}

// Generates a gdb/pwndbg analysis script (text only). Verdex does NOT run it or
// the target — the human runs `gdb -x <script> ./binary` in their own env.
export function pwnGdbScript(value, options = {}) {
  const file = resolveBinary(value);
  const base = path.basename(file);
  const bps = Array.isArray(options.breakpoints) ? options.breakpoints.filter((b) => typeof b === "string" && /^[A-Za-z0-9_.*+]{1,128}$/.test(b)) : [];
  const bpLines = bps.length ? bps.map((b) => `break ${b}`) : ["# break main", "# break *0x401234"];
  const script = [
    `# Verdex 生成的 gdb/pwndbg 分析脚本(仅文本)。`,
    `# 用法: gdb -x this.gdb ./${base}    (由你在自己的环境里运行;Verdex 不执行目标)`,
    `# 建议搭配 pwndbg / gef 以获得 telescope、checksec、堆视图。`,
    `set pagination off`,
    `set disassembly-flavor intel`,
    `file ${base}`,
    ``,
    ...bpLines,
    ``,
    `# run 后常用:`,
    `# info functions           列出函数`,
    `# telescope \\$rsp 20        看栈(pwndbg)`,
    `# x/40gx \\$rsp              看栈原始内容`,
    `# cyclic 200 / cyclic -l <val>   生成/查偏移(pwndbg)`,
    `# vmmap                    内存布局(找可写段/泄露基址)`,
    ``,
    `# run`,
    ``,
  ].join("\n");
  return {
    schema: "VerdexPwn/v1", tool: "pwn_gdbscript", file: base,
    authority: "generated-script", epistemic: "generated", language: "gdb",
    breakpoints: bps, script,
    usage: "审阅后运行 `gdb -x <保存的脚本> ./" + base + "`。Verdex 只生成脚本,不代为运行、不执行目标。",
    limitations: ["仅生成文本脚本;调试与运行由使用者在自己的授权环境中完成。", "Verdex 不执行目标、不连接任何系统。"],
  };
}

export const PWN_TOOLS = [
  {
    name: "pwn_checksec",
    description: "静态读出二进制的利用缓解措施:ELF 的 NX/Canary/PIE/RELRO/Fortify,或 PE 的 DEP/ASLR/CFG/SEH 等。只读分析,不执行、不连接目标。CTF/授权靶场的起手分析。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制路径(ELF 或 PE)。" } } },
    run: (args) => pwnChecksec(args.path),
  },
  {
    name: "pwn_gadgets",
    description: "ROP gadget 搜索:从反汇编里找以 ret 结尾的短指令序列,辅助 CTF exploit 开发。可选 filter(只留含该子串的,如 'pop rdi')和 maxLen(序列最大指令数)。只读,不执行、不连接目标。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制路径。" }, filter: { type: "string", description: "可选:只返回包含此子串的 gadget,如 'pop rdi'。" }, maxLen: { type: "integer", description: "可选:gadget 最大指令数(1-6,默认 4)。" } } },
    run: (args) => pwnGadgets(args.path, { filter: args.filter, maxLen: args.maxLen }),
  },
  {
    name: "pwn_template",
    description: "生成 pwntools exploit 脚手架(仅文本)。target 必填,显式声明授权目标('local' 或 'host:port'),会写进脚本授权 banner。Verdex 只产出脚本、不代为运行/连接;利用由使用者在授权范围(CTF/自建实验室)自行完成。禁止用于未授权系统。",
    inputSchema: { type: "object", required: ["path", "target"], properties: { path: { type: "string", description: "本地二进制路径。" }, target: { type: "string", description: "授权目标声明:'local'(本地进程)或 'host:port'(远程 CTF 题,如 chall.ctf.io:1337)。" } } },
    run: (args) => pwnTemplate(args.path, { target: args.target }),
  },
  {
    name: "pwn_cyclic",
    description: "De Bruijn 循环模式:不传 lookup 时生成模式(length/n),传 lookup(子串或 0x 小端值)时反查溢出偏移。纯计算,不涉及二进制或执行。求栈溢出偏移的标准手法。",
    inputSchema: { type: "object", properties: { length: { type: "integer", description: "生成模式长度(默认 200)。" }, n: { type: "integer", description: "子串宽度,32 位用 4、64 位用 8(默认 4)。" }, lookup: { type: "string", description: "反查:崩溃时 RSP/EIP 的子串或 0x 小端值,返回偏移。" } } },
    run: (args) => pwnCyclic({ length: args.length, n: args.n, lookup: args.lookup }),
  },
  {
    name: "pwn_gdbscript",
    description: "生成 gdb/pwndbg 动态分析脚本(仅文本):设断点、看栈/内存、求偏移的常用命令骨架。由使用者在自己授权环境里 `gdb -x 脚本 ./bin` 运行。Verdex 不执行目标、不连接任何系统。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制路径。" }, breakpoints: { type: "array", items: { type: "string" }, description: "可选:断点列表,如 ['main','*0x401234']。" } } },
    run: (args) => pwnGdbScript(args.path, { breakpoints: args.breakpoints }),
  },
  {
    name: "pwn_libc",
    description: "从 libc.so 提取 exploit 所需偏移:常用符号(system/execve/puts/__free_hook/__malloc_hook/__libc_start_main/environ 等)、/bin/sh 字符串偏移、libc 版本。纯静态读 ELF,只读不执行。堆题/ret2libc 必备。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 libc.so 路径。" } } },
    run: (args) => pwnLibc(args.path),
  },
];
