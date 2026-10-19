import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

// Read-only binary inspection. These tools parse and disassemble a local file;
// they NEVER execute the target binary and never access the network.
const TOOL_TIMEOUT_MS = 30_000;
const MAX_BUFFER = 24 * 1024 * 1024;
const MAX_LINES = 4000;

export function resolveBinary(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地文件路径");
  const file = path.resolve(value);
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error("path 必须指向一个文件");
  return file;
}

export async function run(command, args) {
  try {
    const { stdout } = await execFileAsync(command, args, { timeout: TOOL_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true });
    return stdout;
  } catch (error) {
    if (error.code === "ENOENT") throw new Error(`后端未安装：${command}`);
    // objdump/nm exit non-zero on some formats but still print useful stdout.
    if (error.stdout) return error.stdout;
    throw new Error(`${command} 执行失败：${error.message}`);
  }
}

export function clip(text) {
  const lines = String(text || "").split(/\r?\n/);
  const truncated = lines.length > MAX_LINES;
  return { lines: truncated ? lines.slice(0, MAX_LINES) : lines, truncated, total_lines: lines.length };
}

function envelope(tool, file, backend, body) {
  return {
    schema: "VerdexReverse/v1",
    tool,
    file: path.basename(file),
    authority: "local-binary-static",
    epistemic: "fact",
    backend,
    ...body,
    limitations: [
      "只做静态解析/反汇编，未执行目标二进制，未访问网络。",
      "符号与字符串来自文件现状；加壳、剥离或混淆会降低可见度。",
    ],
  };
}

export async function binInfo(value) {
  const file = resolveBinary(value);
  const [fileType, headers, sections] = await Promise.all([
    run("file", ["-b", file]),
    run("objdump", ["-f", file]),
    run("objdump", ["-h", file]),
  ]);
  return envelope("bin_info", file, "file+objdump", {
    file_type: fileType.trim(),
    header: clip(headers),
    sections: clip(sections),
  });
}

export async function binSymbols(value) {
  const file = resolveBinary(value);
  const [symbols, dynamic] = await Promise.all([
    run("nm", ["-C", file]).catch((error) => `# nm: ${error.message}`),
    run("objdump", ["-T", file]).catch((error) => `# objdump -T: ${error.message}`),
  ]);
  return envelope("bin_symbols", file, "nm+objdump", {
    symbols: clip(symbols),
    dynamic_symbols: clip(dynamic),
  });
}

export async function binStrings(value, options = {}) {
  const file = resolveBinary(value);
  const min = Number.isInteger(options.min) && options.min >= 2 ? options.min : 4;
  const stdout = await run("strings", ["-t", "x", "-n", String(min), file]);
  return envelope("bin_strings", file, "strings", {
    min_length: min,
    strings: clip(stdout),
  });
}

export async function binDisasm(value, options = {}) {
  const file = resolveBinary(value);
  const args = ["-d", "-C", "--no-show-raw-insn"];
  if (typeof options.symbol === "string" && /^[A-Za-z0-9_.$@]{1,128}$/.test(options.symbol)) {
    args.push(`--disassemble=${options.symbol}`);
  }
  args.push(file);
  const stdout = await run("objdump", args);
  return envelope("bin_disasm", file, "objdump", {
    symbol: options.symbol || null,
    epistemic: "fact",
    disassembly: clip(stdout),
  });
}

const DECOMPILE_TIMEOUT_MS = 300_000;
// Set VERDEX_IDA to your idat.exe (or idat64) path. We also probe a few common
// install locations as a convenience; override with VERDEX_IDA when it differs.
const IDA_CANDIDATES = [
  "C:\\Program Files\\IDA Professional 9.2\\idat.exe",
  "C:\\Program Files\\IDA Pro 9.2\\idat.exe",
  "/opt/idapro/idat64",
  "/usr/local/bin/idat64",
];

function findIda() {
  for (const candidate of [process.env.VERDEX_IDA, ...IDA_CANDIDATES].filter(Boolean)) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // keep looking
    }
  }
  return null;
}

const SRC_DIR = path.dirname(fileURLToPath(import.meta.url));
const DUMP_SCRIPT = path.join(SRC_DIR, "ida_dump.py");
const GHIDRA_SCRIPT = path.join(SRC_DIR, "GhidraDecompile.java");
// Set VERDEX_GHIDRA to your Ghidra support/analyzeHeadless[.bat]. A few common
// install locations are probed as a convenience; override when yours differs.
const GHIDRA_CANDIDATES = [
  "C:\\ghidra\\support\\analyzeHeadless.bat",
  "/opt/ghidra/support/analyzeHeadless",
  "/usr/local/ghidra/support/analyzeHeadless",
];

function findGhidra() {
  const env = process.env.VERDEX_GHIDRA;
  const candidates = env ? [env, ...GHIDRA_CANDIDATES] : GHIDRA_CANDIDATES;
  for (const c of candidates) {
    try { if (fs.statSync(c).isFile()) return c; } catch { /* keep looking */ }
  }
  return null;
}

const LIMITS_DECOMPILE = [
  "反编译伪 C 是对二进制的重建推断，不是原始源码；注释、宏、局部变量名在编译后已丢失。",
  "只做静态反编译，未执行目标二进制，未访问网络。",
];

async function decompileWithGhidra(source, symbol) {
  const headless = findGhidra();
  if (!headless) throw new Error("后端未安装：未找到 IDA(idat.exe)也未找到 Ghidra(analyzeHeadless);设置 VERDEX_IDA 或 VERDEX_GHIDRA 指向其一");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-ghidra-"));
  const target = path.join(work, path.basename(source).replace(/[^A-Za-z0-9_.-]/g, "_"));
  const outFile = path.join(work, "decompile.json");
  try {
    fs.copyFileSync(source, target);
    fs.copyFileSync(GHIDRA_SCRIPT, path.join(work, "GhidraDecompile.java"));
    const hlArgs = [work, "verdex_tmp", "-import", target, "-scriptPath", work,
      "-postScript", "GhidraDecompile.java", outFile,
      "-deleteProject", "-analysisTimeoutPerFile", "280"];
    // Windows can't spawn a .bat directly (EINVAL); route through cmd.exe /c.
    const [cmd, args] = headless.toLowerCase().endsWith(".bat")
      ? [process.env.ComSpec || "cmd.exe", ["/c", headless, ...hlArgs]]
      : [headless, hlArgs];
    // Symbol filter is passed to the Ghidra script via env (arg forwarding is unreliable).
    const childEnv = { ...process.env, VERDEX_DECOMPILE_SYMBOL: symbol || "" };
    await execFileAsync(cmd, args, { timeout: DECOMPILE_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true, cwd: work, env: childEnv })
      .catch((error) => { if (!fs.existsSync(outFile)) throw new Error(`Ghidra 执行失败：${error.message}`); });
    if (!fs.existsSync(outFile)) throw new Error("Ghidra 未产出反编译结果");
    const dump = JSON.parse(fs.readFileSync(outFile, "utf8"));
    // Filter to the requested symbol in Node — robust regardless of Ghidra's
    // script arg/env forwarding and its class-name compile cache.
    let functions = dump.functions || [];
    if (symbol) functions = functions.filter((f) => f.name === symbol);
    const env = envelope("bin_decompile", source, "ghidra", {
      epistemic: "inferred", symbol,
      function_count: functions.length,
      functions,
      ...(symbol && functions.length === 0 ? { note: `未找到名为 ${symbol} 的函数(可能已 strip 或名称不同;不传 symbol 可看全部)。` } : {}),
    });
    env.limitations = [...LIMITS_DECOMPILE, "本次用 Ghidra 后端(免费);伪 C 风格与质量与 IDA Hex-Rays 略有差异。"];
    return env;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

export async function binDecompile(value, options = {}) {
  const source = resolveBinary(value);
  const symbol = typeof options.symbol === "string" && /^[A-Za-z0-9_.$@]{1,128}$/.test(options.symbol) ? options.symbol : null;
  const idat = findIda();
  if (!idat) return decompileWithGhidra(source, symbol);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-ida-"));
  const target = path.join(work, path.basename(source).replace(/[^A-Za-z0-9_.-]/g, "_"));
  const outFile = path.join(work, "decompile.json");
  const logFile = path.join(work, "ida.log");
  try {
    fs.copyFileSync(source, target);
    fs.copyFileSync(DUMP_SCRIPT, path.join(work, "ida_dump.py"));
    const scriptArg = symbol ? `ida_dump.py decompile.json ${symbol}` : "ida_dump.py decompile.json";
    await execFileAsync(idat, ["-A", `-S${scriptArg}`, `-L${logFile}`, target], {
      timeout: DECOMPILE_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      windowsHide: true,
      cwd: work,
    }).catch((error) => {
      if (!fs.existsSync(outFile)) throw new Error(`IDA 执行失败：${error.message}`);
    });
    if (!fs.existsSync(outFile)) throw new Error("IDA 未产出反编译结果");
    const dump = JSON.parse(fs.readFileSync(outFile, "utf8"));
    const env = envelope("bin_decompile", source, "ida-hexrays", {
      epistemic: "inferred",
      symbol,
      hexrays: dump.hexrays === true,
      function_count: dump.functions?.length || 0,
      functions: dump.functions || [],
      ...(dump.error ? { backend_error: dump.error } : {}),
    });
    env.limitations = [
      "反编译伪 C 是对二进制的重建推断，不是原始源码；注释、宏、局部变量名在编译后已丢失。",
      "只做静态反编译，未执行目标二进制，未访问网络。",
    ];
    return env;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

// Structured instructions handed to the driving model (e.g. DeepSeek). Verdex
// does not call any LLM itself — it packages evidence + this brief, and the
// model performs the reconstruction in its own reply.
const RECONSTRUCTION_BRIEF = {
  task: "基于反编译伪 C 和证据，重建尽可能接近原始风格的可读源码。",
  priorities: [
    "忠实不幻觉:只写伪 C 与证据支持的内容;推断必须显式标注(如 // [推断]),绝不把猜测写成事实;无法确定的保留原样并注明。",
    "可读性优先:根据用途、调用的 API、引用的字符串,给变量和函数重命名为有意义的名字,并加简洁注释说明意图。",
    "结构恢复:尽量还原 struct/union/枚举定义与完整函数签名(参数类型、返回类型);不确定的字段用注释标注偏移和推断依据。",
    "调用关系:在重建代码里用注释标出关键的函数间调用关系和重要数据流走向,方便理解整体逻辑。",
  ],
  output_format: "对每个函数输出:重建后的源码 + 一段简短说明(重命名依据、不确定点、推断假设)。",
  constraints: [
    "这是对二进制的重建,不是无损还原原始源码;注释、宏、原始局部名在编译后已丢失。",
    "只分析不执行目标;不生成利用代码、载荷或攻击步骤。",
  ],
};

export async function reconstructSource(value, options = {}) {
  const source = resolveBinary(value);
  const symbol = typeof options.symbol === "string" && /^[A-Za-z0-9_.$@]{1,128}$/.test(options.symbol) ? options.symbol : null;
  // Gather evidence in parallel; symbols/strings are best-effort context.
  const [decompile, symbols, strings] = await Promise.all([
    binDecompile(source, symbol ? { symbol } : {}),
    binSymbols(source).catch((error) => ({ backend_error: error.message })),
    binStrings(source, {}).catch((error) => ({ backend_error: error.message })),
  ]);
  const env = envelope("reconstruct", source, "ida-hexrays + model", {
    epistemic: "inferred",
    symbol,
    reconstruction_brief: RECONSTRUCTION_BRIEF,
    pseudocode: decompile.functions || [],
    function_count: decompile.function_count || 0,
    symbols_sample: symbols.symbols ? symbols.symbols : null,
    strings_sample: strings.strings ? { lines: strings.strings.lines.slice(0, 200), truncated: strings.strings.truncated } : null,
    ...(decompile.backend_error ? { backend_error: decompile.backend_error } : {}),
  });
  env.limitations = [
    "本工具只打包证据与重建指令,真正的源码重建由调用方模型(如 DeepSeek)依 reconstruction_brief 产出。",
    "重建结果是推断,非无损还原;Verdex 不调用 LLM、不访问网络、不执行目标。",
  ];
  return env;
}

// Structured per-function dossier (à la REA): disassembly of one symbol +
// the functions it calls + strings it references + optional pseudo-C. Read-only.
export async function binDossier(value, options = {}) {
  const file = resolveBinary(value);
  const symbol = typeof options.symbol === "string" && /^[A-Za-z0-9_.$@]{1,128}$/.test(options.symbol) ? options.symbol : null;
  if (!symbol) throw new Error("bin_dossier 需要 symbol 参数(目标函数名)");

  const dis = await run("objdump", ["-d", "-C", "-M", "intel", "--no-show-raw-insn", `--disassemble=${symbol}`, file]);
  const lines = dis.split(/\r?\n/);
  // calls: `call <0x..> <name>` → collect callee names
  const calls = [];
  const callRx = /\b(?:call|bl|blx|jal)\s+(?:0x)?[0-9a-f]+\s+<([^>+@]+)/i;
  for (const l of lines) { const m = l.match(callRx); if (m) calls.push(m[1]); }
  const uniqueCalls = [...new Set(calls)].slice(0, 100);

  // string xrefs: objdump annotates loads with `# <addr> <...>`; also pull inline string comments
  const strRefs = [];
  for (const l of lines) { const m = l.match(/#\s*[0-9a-f]+\s+<?([^>\n]{3,80})>?\s*$/i); if (m && /[A-Za-z]/.test(m[1])) strRefs.push(m[1].trim()); }

  let pseudocode = null;
  let decompileBackend = null;
  if (findIda() || findGhidra()) {
    try {
      const dec = await binDecompile(file, { symbol });
      const fn = (dec.functions || []).find((f) => f.name === symbol && f.pseudocode) || (dec.functions || []).find((f) => f.pseudocode);
      if (fn) { pseudocode = fn.pseudocode; decompileBackend = dec.backend; }
    } catch { /* decompile optional */ }
  }

  const env = envelope("bin_dossier", file, decompileBackend ? `objdump + ${decompileBackend}` : "objdump", {
    epistemic: "inferred",
    symbol,
    disassembly: clip(dis),
    calls_out: uniqueCalls,
    string_xrefs: [...new Set(strRefs)].slice(0, 50),
    ...(pseudocode ? { pseudocode } : { pseudocode_note: "未装 IDA/Ghidra,档案只含反汇编+调用+字符串;装了反编译器会附伪 C" }),
  });
  env.limitations = [
    "单函数档案:反汇编为事实,调用/字符串为从反汇编抽取,伪 C(若有)是重建推断。",
    "只静态分析,未执行目标。",
  ];
  return env;
}

export const REVERSE_TOOLS = [
  {
    name: "bin_dossier",
    description: "单函数结构化档案(对标 REA function dossier):给一个 symbol,产出它的反汇编 + 它调用的函数(calls_out)+ 引用的字符串(string_xrefs)+ 伪 C(装了 IDA/Ghidra 时)。快速看懂一个函数在干什么。只读,不执行。",
    inputSchema: { type: "object", required: ["path", "symbol"], properties: { path: { type: "string", description: "本地二进制路径。" }, symbol: { type: "string", description: "目标函数名。" } } },
    run: (args) => binDossier(args.path, { symbol: args.symbol }),
  },
  {
    name: "bin_info",
    description: "二进制事实:文件类型、架构、ELF/PE 头、段表(file + objdump)。只读,不执行目标文件,不访问网络。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" } } },
    run: (args) => binInfo(args.path),
  },
  {
    name: "bin_symbols",
    description: "二进制符号:静态符号表与动态导入导出(nm + objdump -T)。只读,不执行目标。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" } } },
    run: (args) => binSymbols(args.path),
  },
  {
    name: "bin_strings",
    description: "二进制可打印字符串及其文件偏移(strings)。只读,不执行目标。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" }, min: { type: "integer", description: "最小字符串长度,默认 4。" } } },
    run: (args) => binStrings(args.path, { min: args.min }),
  },
  {
    name: "bin_disasm",
    description: "反汇编(objdump -d),可选只反汇编某个符号。确定性反汇编,只读,不执行目标。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" }, symbol: { type: "string", description: "可选:只反汇编该符号/函数名。" } } },
    run: (args) => binDisasm(args.path, { symbol: args.symbol }),
  },
  {
    name: "bin_decompile",
    description: "用 IDA Pro(Hex-Rays)headless 反编译出伪 C。结果是对二进制的重建推断,非原始源码(注释/宏/局部名已丢失)。只静态分析,不执行目标。需本机装 IDA。可选 symbol 只反编译单个函数(更快)。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" }, symbol: { type: "string", description: "可选:只反编译该函数名。不传则全量反编译。" } } },
    run: (args) => binDecompile(args.path, { symbol: args.symbol }),
  },
  {
    name: "reconstruct",
    description: "源码重建:打包伪 C(IDA)+符号+字符串+结构化重建指令,交由调用方模型(如 DeepSeek)重命名、补类型、加注释、译回接近原始风格的可读源码。Verdex 自身不调 LLM、不联网、不执行目标;重建结果是推断非无损还原。可选 symbol 只重建单函数。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地二进制文件路径。" }, symbol: { type: "string", description: "可选:只重建该函数名。不传则全量。" } } },
    run: (args) => reconstructSource(args.path, { symbol: args.symbol }),
  },
];
