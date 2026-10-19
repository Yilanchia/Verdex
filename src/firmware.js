import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

// Pure-Node firmware triage (a mini-binwalk): scans an image for embedded
// filesystem / compression / bootloader signatures and maps entropy to spot
// encrypted or compressed regions. Read-only; extracts nothing, runs nothing.
// Tells you WHAT is inside and WHERE, and which tool to extract it with.

const MAX_SCAN = 64 * 1024 * 1024; // cap very large images
const MAX_BUFFER = 32 * 1024 * 1024;

// Each signature: bytes (hex), label, and the tool to extract it.
const SIGS = [
  { hex: "68737173", label: "SquashFS (little-endian)", tool: "unsquashfs / sasquatch" },
  { hex: "73717368", label: "SquashFS (big-endian)", tool: "unsquashfs" },
  { hex: "7371736800", label: "SquashFS (sqsh)", tool: "unsquashfs" },
  { hex: "28cd3d45", label: "CramFS", tool: "cramfsck / uncramfs" },
  { hex: "1985", label: "JFFS2 node (LE)", tool: "jefferson", weak: true },
  { hex: "8519", label: "JFFS2 node (BE)", tool: "jefferson", weak: true },
  { hex: "55424923", label: "UBI image (UBI#)", tool: "ubireader_extract_images" },
  { hex: "31181006", label: "UBIFS", tool: "ubireader_extract_files" },
  { hex: "27051956", label: "U-Boot uImage header", tool: "dumpimage / binwalk" },
  { hex: "48445230", label: "TRX firmware (HDR0)", tool: "binwalk / trx 工具" },
  { hex: "d00dfeed", label: "Flattened Device Tree (DTB)", tool: "dtc -I dtb" },
  { hex: "414e44524f494421", label: "Android boot image (ANDROID!)", tool: "unpack_bootimg / abootimg" },
  { hex: "30373037", label: "cpio archive (ascii)", tool: "cpio -idv" },
  { hex: "1f8b08", label: "gzip 压缩流", tool: "gunzip" },
  { hex: "fd377a585a00", label: "xz 压缩流", tool: "unxz" },
  { hex: "425a68", label: "bzip2 压缩流", tool: "bunzip2" },
  { hex: "5d0000", label: "LZMA 流(启发式,可能误报)", tool: "unlzma", weak: true },
  { hex: "894c5a4f", label: "LZO 压缩(LZO 魔数)", tool: "lzop -d" },
  { hex: "7f454c46", label: "ELF 可执行/库", tool: "bin_decompile(Verdex 内置)" },
  { hex: "2d2d2d2d2d424547494e", label: "PEM 块(证书/私钥, -----BEGIN)", tool: "openssl / secrets(Verdex)" },
];

function entropyOf(buf) {
  if (buf.length === 0) return 0;
  const freq = new Array(256).fill(0);
  for (const b of buf) freq[b]++;
  let e = 0;
  for (const c of freq) { if (c) { const p = c / buf.length; e -= p * Math.log2(p); } }
  return e; // 0..8 bits/byte
}

export function scanFirmware(value, options = {}) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地固件镜像路径");
  const file = path.resolve(value);
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error("path 必须指向一个文件");
  const full = fs.readFileSync(file);
  const buf = full.length > MAX_SCAN ? full.subarray(0, MAX_SCAN) : full;

  // --- signature scan ---
  const sigs = SIGS.map((s) => ({ ...s, needle: Buffer.from(s.hex, "hex") }));
  const hits = [];
  const maxHitsPerSig = 50;
  for (const s of sigs) {
    let from = 0, count = 0;
    while (count < maxHitsPerSig) {
      const idx = buf.indexOf(s.needle, from);
      if (idx === -1) break;
      // Skip weak/short signatures unless they look offset-aligned-ish or at 0.
      hits.push({ offset: idx, offset_hex: `0x${idx.toString(16)}`, type: s.label, extract_with: s.tool, ...(s.weak ? { weak: true } : {}) });
      from = idx + Math.max(1, s.needle.length);
      count++;
    }
  }
  hits.sort((a, b) => a.offset - b.offset);

  // --- entropy map (sliding window) ---
  const win = Number.isInteger(options.window) && options.window >= 256 ? options.window : 4096;
  const segments = [];
  for (let off = 0; off < buf.length; off += win) {
    const slice = buf.subarray(off, Math.min(off + win, buf.length));
    segments.push({ offset: off, offset_hex: `0x${off.toString(16)}`, entropy: Number(entropyOf(slice).toFixed(2)), size: slice.length });
  }
  // Flag contiguous high-entropy regions (>7.2 ≈ compressed/encrypted).
  const highRegions = [];
  let runStart = null;
  for (let i = 0; i <= segments.length; i++) {
    const high = i < segments.length && segments[i].entropy >= 7.2;
    if (high && runStart === null) runStart = segments[i].offset;
    else if (!high && runStart !== null) {
      highRegions.push({ start_hex: `0x${runStart.toString(16)}`, end_hex: `0x${(segments[i - 1].offset + segments[i - 1].size).toString(16)}` });
      runStart = null;
    }
  }
  const overall = Number(entropyOf(buf.subarray(0, Math.min(buf.length, 1024 * 1024))).toFixed(2));

  const byType = {};
  for (const h of hits) byType[h.type] = (byType[h.type] || 0) + 1;

  return {
    schema: "VerdexFirmware/v1",
    tool: "fw_scan",
    file: path.basename(file),
    authority: "local-binary-static",
    epistemic: "inferred",
    size: stat.size,
    scanned: buf.length,
    overall_entropy: overall,
    likely_encrypted: overall >= 7.5 && hits.length === 0,
    signature_count: hits.length,
    by_type: byType,
    signatures: hits.slice(0, 500),
    high_entropy_regions: highRegions.slice(0, 100),
    next_steps: "按 signatures 的 offset 用对应 extract_with 工具提取文件系统/压缩块;解出 rootfs 后:ELF→bin_decompile,配置/脚本→scan,凭据→secrets。",
    limitations: [
      "只做特征匹配与熵分析,未解包、未执行任何固件内容。",
      "特征是启发式:弱特征(LZMA 等)可能误报;整体高熵且无特征可能是加密固件。",
      "仅限你拥有或被授权分析的设备固件;禁止用于未授权目标。",
    ],
  };
}

const WSL_DISTRO = process.env.VERDEX_WSL_DISTRO || "Ubuntu-24.04";

const EXTRACT_TIMEOUT_MS = 300_000;

// Per-filesystem extractor argv builders. src/dst are the already-resolved
// paths for the current platform (native) or will be mnt-translated for WSL.
const EXTRACTORS = {
  squashfs: { cmd: "unsquashfs", args: (src, dst) => ["-f", "-d", dst, src] },
  jffs2: { cmd: "jefferson", args: (src, dst) => [src, "-d", dst] },
  ubifs: { cmd: "ubireader_extract_files", args: (src, dst) => ["-o", dst, src] },
};

// On Windows, firmware extractors run inside WSL; on Linux they run natively.
function extractorFor(fsType) {
  const spec = EXTRACTORS[fsType];
  if (!spec) throw new Error(`无解包器:${fsType}`);
  if (process.platform === "win32") {
    const toWsl = (p) => "/mnt/" + p[0].toLowerCase() + p.slice(2).replace(/\\/g, "/");
    return {
      backend: `wsl:${WSL_DISTRO}/${spec.cmd}`,
      async run(winSrc, winDst) {
        const src = toWsl(path.resolve(winSrc));
        const dst = toWsl(path.resolve(winDst));
        await execFileAsync("wsl.exe", ["-d", WSL_DISTRO, "-u", "root", "--", spec.cmd, ...spec.args(src, dst)],
          { timeout: EXTRACT_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true });
      },
    };
  }
  return {
    backend: spec.cmd,
    async run(src, dst) {
      await execFileAsync(spec.cmd, spec.args(path.resolve(src), path.resolve(dst)), { timeout: EXTRACT_TIMEOUT_MS, maxBuffer: MAX_BUFFER, windowsHide: true });
    },
  };
}

function detectFsType(file) {
  const fd = fs.openSync(file, "r");
  try {
    const b = Buffer.alloc(4); fs.readSync(fd, b, 0, 4, 0);
    const m4 = b.toString("hex");
    if (m4 === "68737173" || m4 === "73717368") return "squashfs";
    if (m4 === "55424923") return "ubifs"; // "UBI#"
    const m2 = b.subarray(0, 2).toString("hex");
    if (m2 === "8519" || m2 === "1985") return "jffs2";
    return null;
  } finally { fs.closeSync(fd); }
}

function classifyFsFile(rel, abs) {
  const lower = rel.toLowerCase();
  try {
    const fd = fs.openSync(abs, "r");
    try {
      const b = Buffer.alloc(4); fs.readSync(fd, b, 0, 4, 0);
      if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) return "native";
    } finally { fs.closeSync(fd); }
  } catch { /* ignore */ }
  if (/(passwd|shadow|\.pem|\.key|_rsa|_dsa|authorized_keys)$/.test(lower)) return "credential";
  if (/\.(sh|rc)$|(^|\/)(init|rcs|profile)$/.test(lower)) return "script";
  if (/(^|\/)etc\//.test("/" + lower) || /\.(conf|cfg|ini|json|xml|env)$/.test(lower)) return "config";
  return "other";
}

function walkFs(dir, base, acc, cap) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (acc.length >= cap) return;
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) walkFs(abs, base, acc, cap);
    else if (entry.isFile()) { try { acc.push({ rel: path.relative(base, abs).replace(/\\/g, "/"), abs, size: fs.statSync(abs).size }); } catch { /* skip */ } }
  }
}

// Extracts a SquashFS firmware image to a rootfs and inventories it, routing
// files to the right Verdex tool. Read-only; never executes firmware content.
export async function fwExtract(value) {
  if (typeof value !== "string" || !value.trim()) throw new Error("参数 path 必须是本地固件/文件系统镜像路径");
  const file = path.resolve(value);
  if (!fs.statSync(file).isFile()) throw new Error("path 必须指向一个文件");
  const fsType = detectFsType(file);
  if (!fsType) {
    throw new Error("无法识别的文件系统(支持 SquashFS/JFFS2/UBIFS);其他格式先用 fw_scan 定位偏移,再用对应工具提取");
  }

  const runner = extractorFor(fsType);
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-rootfs-"));
  // Extractors like jefferson refuse a pre-existing dest, so point them at a
  // subdir that does not exist yet; each tool creates it.
  const outDir = path.join(workDir, "fs");
  const keepDir = fs.mkdtempSync(path.join(os.tmpdir(), "verdex-fw-native-"));
  try {
    await runner.run(file, outDir).catch((e) => {
      const hint = process.platform === "win32" ? "(Windows 经 WSL 调用;确认 WSL 里已装 squashfs-tools/jefferson/ubi_reader,或设 VERDEX_WSL_DISTRO)" : "";
      throw new Error(`${fsType} 解包失败:${e.message.split("\n")[0]} ${hint}`);
    });
    const files = [];
    walkFs(outDir, outDir, files, 20000);
    const buckets = { native: [], config: [], script: [], credential: [], other: [] };
    for (const f of files) buckets[classifyFsFile(f.rel, f.abs)].push(f);

    const native = buckets.native.slice(0, 200).map((n) => {
      const out = path.join(keepDir, path.basename(n.rel));
      try { fs.copyFileSync(n.abs, out); } catch { /* skip */ }
      return { path: n.rel, size: n.size, extracted_to: out };
    });
    const inventory = Object.fromEntries(Object.entries(buckets).map(([k, v]) => [k, v.length]));
    return {
      schema: "VerdexFirmware/v1",
      tool: "fw_extract",
      file: path.basename(file),
      fs_type: fsType,
      backend: runner.backend,
      file_count: files.length,
      inventory,
      native_binaries: native,
      config_files: buckets.config.slice(0, 200).map((f) => f.rel),
      scripts: buckets.script.slice(0, 100).map((f) => f.rel),
      credential_files: buckets.credential.slice(0, 100).map((f) => f.rel),
      rootfs_dir: outDir,
      next_steps: "native→bin_decompile(ELF);config/script→scan;rootfs 整个目录→secrets 扫硬编码凭据。rootfs 已解到 rootfs_dir。",
      limitations: [
        "只解包 SquashFS 并清点,未执行固件内任何程序。",
        "Windows 下经 WSL 的 unsquashfs 完成解包;Linux 原生调用。",
        "仅限你拥有或被授权分析的设备固件;禁止用于未授权目标。",
      ],
    };
  } catch (err) {
    fs.rmSync(workDir, { recursive: true, force: true, maxRetries: 2 });
    fs.rmSync(keepDir, { recursive: true, force: true, maxRetries: 2 });
    throw err;
  }
  // On success, keepDir (extracted native binaries) and rootfs_dir are
  // intentionally retained so follow-up tools (bin_decompile/scan/secrets)
  // can read them; OS temp cleanup reclaims them later.
}

export const FIRMWARE_TOOLS = [
  {
    name: "fw_extract",
    description: "解包固件文件系统镜像(SquashFS/JFFS2/UBIFS;Windows 经 WSL,Linux 原生;调 unsquashfs/jefferson/ubireader)并清点 rootfs:原生 ELF(抽出可喂 bin_decompile)、配置、脚本、凭据文件。只读不执行固件。需 WSL 里装 squashfs-tools/jefferson/ubi_reader。仅限你拥有或被授权的设备固件。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地 SquashFS 镜像路径。" } } },
    run: (args) => fwExtract(args.path),
  },
  {
    name: "fw_scan",
    description: "固件镜像分流(mini-binwalk,纯静态):扫描内嵌文件系统(SquashFS/CramFS/JFFS2/UBI)、压缩块(gzip/xz/lzma/bzip2)、引导头(U-Boot/TRX/DTB/Android boot)、ELF、PEM 的特征与偏移,并给熵分布图标出加密/压缩区段;每个命中附建议解包工具。只读,不解包不执行。仅限你拥有或被授权的设备固件。",
    inputSchema: { type: "object", required: ["path"], properties: { path: { type: "string", description: "本地固件镜像路径(.bin/.img/.trx 等)。" }, window: { type: "integer", description: "熵分析滑窗字节数(默认 4096)。" } } },
    run: (args) => scanFirmware(args.path, { window: args.window }),
  },
];
