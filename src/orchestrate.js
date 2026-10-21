import fs from "node:fs";
import path from "node:path";
import { isDotnetAssembly } from "./dotnet.js";

// Router: detect what a target IS and return the recommended Verdex tool chain,
// so the driving model can analyze any target from a single entry point.
// Pure detection (magic bytes + extension + stat) — runs no heavy analysis.

function magic(file) {
  try {
    const fd = fs.openSync(file, "r");
    try { const b = Buffer.alloc(8); fs.readSync(fd, b, 0, 8, 0); return b; } finally { fs.closeSync(fd); }
  } catch { return Buffer.alloc(0); }
}

function detectFileType(file, b) {
  // A PE that carries CLR metadata is a .NET assembly, not a native PE.
  if (b.subarray(0, 2).toString("hex") === "4d5a" && isDotnetAssembly(file)) return "dotnet";
  const ext = (file.match(/\.[^.\\/]+$/) || [""])[0].toLowerCase();
  const hex4 = b.subarray(0, 4).toString("hex");
  const hex2 = b.subarray(0, 2).toString("hex");
  // archives (zip-based) by extension first (all start with PK)
  if (hex2 === "504b") {
    if (ext === ".apk" || ext === ".aab" || ext === ".xapk") return "android-apk";
    if (ext === ".ipa") return "ios-ipa";
    if (ext === ".jar") return "java-jar";
    return "zip";
  }
  if (ext === ".wxapkg" || b[0] === 0xbe) return "wechat-miniprogram";
  if (hex4 === "7f454c46") return "elf";
  if (hex2 === "4d5a") return "pe";
  if (["feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca"].includes(hex4)) return "macho";
  if (hex4 === "64657800" || ext === ".dex" || b.subarray(0, 3).toString() === "dex") return "dex";
  if (hex4 === "68737173" || hex4 === "73717368") return "firmware-squashfs";
  if (hex4 === "55424923") return "firmware-ubifs";
  if (hex2 === "8519" || hex2 === "1985") return "firmware-jffs2";
  if (ext === ".asar") return "electron-asar";
  if (ext === ".har") return "har";
  if ([".js", ".mjs", ".jsx", ".ts", ".tsx", ".wxs"].includes(ext)) return "javascript";
  if (ext === ".so" || ext === ".dylib") return "elf"; // shared lib, treat as native
  if (ext === ".bin" || ext === ".img" || ext === ".trx") return "firmware-unknown";
  return "unknown-file";
}

// Ordered tool chains per target type. Each step: tool name + why.
const CHAINS = {
  directory: [
    ["scan", "静态扫描:资产/规则命中/数据流候选"],
    ["secrets", "扫硬编码密钥(服务商特征+高熵)"],
    ["map", "代码图:路由/调用/数据流(需要时)"],
    ["osint", "本地脱敏 OSINT 提取(需要时)"],
    ["report", "汇总成不可变快照 + HTML/SARIF 报告"],
  ],
  elf: [["bin_info", "文件类型/架构/段"], ["pwn_checksec", "缓解措施(若做 pwn)"], ["bin_decompile", "反编译伪 C(IDA/Ghidra)"], ["reconstruct", "大模型重建可读源码"]],
  pe: [["bin_info", "文件类型/架构"], ["pwn_checksec", "DEP/ASLR/CFG"], ["bin_decompile", "反编译伪 C"]],
  dotnet: [["dotnet_decompile", "ILSpy 反编译成 C#(托管程序集)"], ["secrets", "对反编译结果扫硬编码密钥"]],
  macho: [["bin_info", "Mach-O 头/架构"], ["bin_decompile", "反编译伪 C(iOS/macOS 原生)"]],
  "android-apk": [["mobile_unpack", "解包清点(原生库/DEX/资源)"], ["dex_decompile", "DEX→Java(jadx)"], ["bin_decompile", "对 lib/*.so 原生库反编译"], ["secrets", "对解包目录扫密钥"]],
  "ios-ipa": [["mobile_unpack", "解包清点"], ["bin_decompile", "对 Payload 内 Mach-O 反编译"]],
  "java-jar": [["mobile_unpack", "解包"], ["dex_decompile", "若含 dex;否则看 .class(未内置)"]],
  "wechat-miniprogram": [["wxapkg_unpack", "解包 js/wxml/wxss/json"], ["js_deobfuscate", "对 js 反转义/美化/特征"], ["scan", "对解包目录静态分析"]],
  dex: [["dex_decompile", "DEX→Java(jadx)"]],
  "firmware-squashfs": [["fw_scan", "分流(看里面有啥)"], ["fw_extract", "解包 SquashFS → rootfs"], ["bin_decompile", "对 rootfs 的 ELF 反编译"], ["secrets", "对 rootfs 扫凭据"]],
  "firmware-jffs2": [["fw_scan", "分流"], ["fw_extract", "解包 JFFS2(jefferson)→ rootfs"], ["secrets", "扫凭据"]],
  "firmware-ubifs": [["fw_scan", "分流"], ["fw_extract", "解包 UBIFS(ubireader)→ rootfs"], ["secrets", "扫凭据"]],
  "firmware-unknown": [["fw_scan", "分流:识别内嵌文件系统/压缩/引导头 + 熵图"], ["fw_extract", "若识别出 SquashFS/JFFS2/UBI 则解包"]],
  javascript: [["js_deobfuscate", "反转义/美化/混淆特征/提取 URL"], ["scan", "对所在目录做静态分析"]],
  har: [["har_analyze", "抓包流量静态分析(安全头/cookie/CORS/反射)"]],
  "electron-asar": [["asar_unpack", "解包 Electron 归档"], ["js_deobfuscate", "对主/渲染进程 js 反混淆"], ["scan", "对解包目录静态分析"]],
  zip: [["mobile_unpack", "按 ZIP 解包清点(若是 app 包)"]],
  "unknown-file": [["bin_info", "先看文件类型"], ["fw_scan", "若疑似固件,做特征+熵分流"]],
  domain: [["web_recon", "为授权域名生成分阶段侦察剧本(被动→轻主动→主动)"]],
};

// A bare domain / URL (common for public-SRC scopes that only give a host).
function looksLikeDomain(value) {
  const v = value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  return /^(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v) && !/[\\/]/.test(value.replace(/^https?:\/\//i, "").replace(/\/.*$/, ""));
}

export function analyzeTarget(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地路径或授权域名");
  // Domain/URL target (SRC gives only a host) → recon playbook, not a file.
  if (!fs.existsSync(path.resolve(value.replace(/^https?:\/\//i, "").split(/[\\/]/)[0])) && looksLikeDomain(value)) {
    const d = value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    return {
      schema: "VerdexOrchestrate/v1",
      tool: "analyze_target",
      target: d,
      is_directory: false,
      target_type: "domain",
      recommended_tools: CHAINS.domain.map(([tool, why], i) => ({ step: i + 1, tool: `mcp__verdex__${tool}`, why })),
      note: "目标是域名(非本地文件):先用 web_recon 生成侦察剧本。仅对授权范围(公益 SRC/书面 scope)的域执行,命令由你在授权内运行。",
      limitations: ["只做识别与路由;web_recon 只产剧本文本,不向任何目标发请求。"],
    };
  }
  const target = path.resolve(value);
  const stat = fs.statSync(target); // throws if missing
  const type = stat.isDirectory() ? "directory" : detectFileType(target, magic(target));
  const chain = CHAINS[type] || CHAINS["unknown-file"];
  return {
    schema: "VerdexOrchestrate/v1",
    tool: "analyze_target",
    target,
    is_directory: stat.isDirectory(),
    target_type: type,
    recommended_tools: chain.map(([tool, why], i) => ({ step: i + 1, tool: `mcp__verdex__${tool}`, why })),
    note: "这是路由建议:按 recommended_tools 顺序调用对应工具即可完成分析。每个工具都只读/只产文本,利用动作仍需在授权范围由人完成。",
    limitations: [
      "按魔数/扩展名识别类型;加壳、改扩展名或少见格式可能识别为 unknown-file。",
      "本工具只做识别与路由,不执行任何重分析;实际分析由被推荐的工具完成。",
    ],
  };
}

export const ORCHESTRATE_TOOLS = [
  {
    name: "analyze_target",
    description: "一站式入口:识别目标类型(目录/ELF/PE/Mach-O/APK/IPA/小程序/DEX/固件 SquashFS·JFFS2·UBI/JS/HAR),返回推荐的 Verdex 工具链(有序+理由)。丢个路径就知道该怎么分析。只做识别与路由,不执行重分析。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地目标路径(目录或文件)。" } } },
    run: (args) => analyzeTarget(args.path),
  },
];
