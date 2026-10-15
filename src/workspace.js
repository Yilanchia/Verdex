import fs from "node:fs";
import path from "node:path";
import { hashBytes } from "./evidence.js";

export const SKIP_DIRS = new Set([
  ".git", ".idea", ".next", "node_modules", "dist", "build", "coverage",
  "vendor", "target", "verdex", ".verdex", ".tmp-report", ".venv", "venv", "__pycache__",
]);

export const TEXT_EXTENSIONS = new Set([
  ".c", ".cc", ".cpp", ".conf", ".config", ".cs", ".cfg", ".go", ".h",
  ".html", ".java", ".js", ".json", ".jsonl", ".jsx", ".kt", ".log", ".md",
  ".mjs", ".php", ".py", ".rb", ".rs", ".sql", ".svelte", ".toml", ".ts",
  ".tsx", ".txt", ".vue", ".xml", ".yaml", ".yml", ".env", ".csv", ".list",
  ".ini",
]);

const SPECIAL_NAMES = new Set(["dockerfile", "makefile", "scope", "hosts", "urls", "domains", "targets", ".env", ".env.example"]);

export function resolveRoot(value) {
  const root = path.resolve(value || process.cwd());
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`Directory does not exist: ${root}`);
  return fs.realpathSync(root);
}

export function collectWorkspace(value, options = {}) {
  const root = resolveRoot(value);
  const maxFiles = positiveLimit(options.maxFiles, 1200);
  const maxBytes = positiveLimit(options.maxBytes, 512_000);
  const maxEntries = positiveLimit(options.maxEntries, 50_000);
  const files = [];
  const omissions = [];
  const counts = {};
  let visited = 0;
  let enumerationComplete = true;

  function omit(file, reason) {
    counts[reason] = (counts[reason] || 0) + 1;
    if (omissions.length < 100) omissions.push({ file: relativePath(root, file), reason });
  }

  function walk(directory) {
    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    } catch {
      omit(directory, "unreadable-directory");
      return;
    }
    for (const entry of entries) {
      visited += 1;
      if (visited > maxEntries) {
        enumerationComplete = false;
        return;
      }
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        omit(full, "symlink");
        continue;
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) omit(full, "excluded-directory");
        else walk(full);
        if (!enumerationComplete) return;
        continue;
      }
      if (!entry.isFile() || !isTextFile(full)) continue;
      if (files.length >= maxFiles) {
        omit(full, "file-limit");
        continue;
      }
      try {
        const bytes = fs.readFileSync(full);
        if (bytes.length > maxBytes) {
          omit(full, "size-limit");
          continue;
        }
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        if (text.includes("\0")) {
          omit(full, "binary-content");
          continue;
        }
        files.push({ path: relativePath(root, full), full, text, content_sha256: hashBytes(bytes) });
      } catch {
        omit(full, "unreadable-or-non-utf8-file");
      }
    }
  }

  walk(root);
  const incomplete = !enumerationComplete || Object.keys(counts).some((reason) => reason !== "excluded-directory");
  return {
    root,
    files,
    coverage: {
      status: incomplete ? "partial" : "complete",
      files_read: files.length,
      enumeration_complete: enumerationComplete,
      truncated: Boolean(counts["file-limit"] || counts["size-limit"] || !enumerationComplete),
      omitted: counts,
      omission_sample: omissions,
      limits: { max_files: maxFiles, max_file_bytes: maxBytes, max_entries: maxEntries },
    },
  };
}

export function listFiles(root, limit = 1200) {
  return collectWorkspace(root, { maxFiles: limit }).files.map((file) => file.full);
}

export function readText(file) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(file));
  } catch {
    return null;
  }
}

export function relativePath(root, file) {
  return path.relative(root, file).split(path.sep).join("/");
}

export function isTextFile(file) {
  const name = path.basename(file).toLowerCase();
  return SPECIAL_NAMES.has(name) || TEXT_EXTENSIONS.has(path.extname(name));
}

function positiveLimit(value, fallback) {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 1) throw new Error("Limits must be positive integers");
  return value;
}
