import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { packageInfo } from "./package-info.js";
import { findGhidra, findIda } from "./reverse.js";
import { findJadx } from "./mobile.js";
import { findDotnet, findIlspy } from "./dotnet.js";
import { toolCatalog } from "./mcp.js";

const execFileAsync = promisify(execFile);
const PROBE_TIMEOUT_MS = 8000;

// `verdex doctor` — local, read-only environment diagnostics. It never runs a
// target and never touches the network; it only checks whether the optional
// decompiler/extractor backends are present and where they live, so a new user
// can tell "tool missing" from "tool broken".
async function probe(command, args = ["--version"]) {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: PROBE_TIMEOUT_MS,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    const first = String(stdout || stderr || "").split(/\r?\n/).find((line) => line.trim());
    return { ok: true, detail: (first || "present").trim().slice(0, 160) };
  } catch (error) {
    if (error.code === "ENOENT") return { ok: false, detail: "not found on PATH" };
    return { ok: false, detail: String(error.message || error).split(/\r?\n/)[0].slice(0, 160) };
  }
}

function backend(id, label, status, extra = {}) {
  return { id, label, status, path: extra.path || null, env: extra.env || null, detail: extra.detail || null, affects: extra.affects || [], hint: extra.hint || null };
}

export async function doctor() {
  const pkg = packageInfo();
  const tools = toolCatalog();
  const backends = [];

  // binutils: the static baseline for bin_info/bin_symbols/bin_strings/bin_disasm.
  const binutils = ["objdump", "nm", "strings", "file"];
  const binutilsProbes = await Promise.all(binutils.map((command) => probe(command)));
  const present = binutils.filter((_, index) => binutilsProbes[index].ok);
  backends.push(
    backend("binutils", "binutils: objdump / nm / strings / file", present.length === binutils.length ? "ok" : present.length ? "partial" : "missing", {
      detail: present.length === binutils.length ? "all four present" : `present: ${present.join(", ") || "none"}`,
      affects: ["bin_info", "bin_symbols", "bin_strings", "bin_disasm", "bin_dossier", "pwn_gadgets", "reconstruct", "pwn_checksec"],
      hint: "Install binutils + file (Windows: MSYS2/ucrt64). Without them only the pure-JS analyzers work.",
    }),
  );

  const ida = findIda();
  backends.push(
    backend("ida", "IDA Pro / Hex-Rays (idat)", ida ? "ok" : "missing", {
      path: ida,
      env: "VERDEX_IDA",
      affects: ["bin_decompile", "reconstruct", "bin_dossier"],
      hint: "Optional commercial backend. Set VERDEX_IDA to idat.exe/idat64, or install Ghidra instead.",
    }),
  );

  const ghidra = findGhidra();
  backends.push(
    backend("ghidra", "Ghidra headless (analyzeHeadless)", ghidra ? "ok" : "missing", {
      path: ghidra,
      env: "VERDEX_GHIDRA",
      affects: ["bin_decompile", "reconstruct", "bin_dossier"],
      hint: "Free fallback for bin_decompile. Set VERDEX_GHIDRA to support/analyzeHeadless[.bat]; needs JDK 21+.",
    }),
  );

  const java = await probe("java", ["-version"]);
  backends.push(
    backend("java", "JDK (java)", java.ok ? "ok" : "missing", {
      detail: java.detail,
      affects: ["bin_decompile (Ghidra)", "dex_decompile (jadx)"],
      hint: "Ghidra needs JDK 21+; jadx needs JDK 11+.",
    }),
  );

  const jadx = findJadx();
  backends.push(
    backend("jadx", "jadx (DEX to Java)", jadx ? "ok" : "missing", {
      path: jadx,
      env: "VERDEX_JADX",
      affects: ["dex_decompile"],
      hint: "Set VERDEX_JADX to bin/jadx (or jadx.bat) to decompile APK/DEX.",
    }),
  );

  const dotnet = findDotnet();
  const dotnetProbe = await probe(dotnet, ["--version"]);
  const ilspy = findIlspy();
  backends.push(
    backend("dotnet", ".NET runtime (dotnet)", dotnetProbe.ok ? "ok" : "missing", {
      path: dotnetProbe.ok ? dotnet : null,
      detail: dotnetProbe.detail,
      env: "VERDEX_DOTNET",
      affects: ["dotnet_decompile"],
      hint: "Needed to host ilspycmd for .NET decompilation.",
    }),
  );
  backends.push(
    backend("ilspy", "ilspycmd (ILSpy)", ilspy ? "ok" : "missing", {
      path: ilspy,
      env: "VERDEX_ILSPY",
      affects: ["dotnet_decompile"],
      hint: "Install ILSpy's dotnet tool and set VERDEX_ILSPY to ilspycmd.dll.",
    }),
  );

  if (process.platform === "win32") {
    const wsl = await probe("wsl.exe", ["--status"]);
    backends.push(
      backend("wsl", "WSL (firmware extraction)", wsl.ok ? "ok" : "missing", {
        detail: wsl.ok ? "WSL present; needs squashfs-tools inside the distro" : wsl.detail,
        env: "VERDEX_WSL_DISTRO",
        affects: ["fw_extract"],
        hint: "Windows routes SquashFS extraction through WSL; install squashfs-tools in the distro.",
      }),
    );
  } else {
    const unsquashfs = await probe("unsquashfs", ["-version"]);
    backends.push(
      backend("unsquashfs", "squashfs-tools (unsquashfs)", unsquashfs.ok ? "ok" : "missing", {
        detail: unsquashfs.detail,
        affects: ["fw_extract"],
        hint: "Install squashfs-tools to extract SquashFS firmware images.",
      }),
    );
  }

  const ok = backends.filter((item) => item.status === "ok").length;
  const partial = backends.filter((item) => item.status === "partial").length;
  const missing = backends.filter((item) => item.status === "missing").length;
  const nextSteps = backends
    .filter((item) => item.status !== "ok" && item.id !== "wsl")
    .map((item) => `${item.id}: ${item.hint}`);

  return {
    schema: "VerdexDoctor/v1",
    package: { name: pkg.name, version: pkg.version },
    runtime: {
      node: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      profile: process.env.VERDEX_PROFILE === "pwn" ? "pwn" : "full",
      tools_visible: tools.length,
    },
    backends,
    summary: { ok, partial, missing },
    next_steps: nextSteps,
    limitations: [
      "只做本机存在性探测:探测到后端不等于该后端能成功分析每一个目标。",
      "doctor 不运行目标文件、不发网络请求,也不会修改你的环境。",
    ],
  };
}
