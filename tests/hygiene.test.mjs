import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// Regression guard for the 0.2.0 scrub: real engagement identifiers, app keys
// and local user paths must never come back into tracked files. The patterns
// are intentionally repo-specific (not a generic secret scanner) so test
// fixtures can still contain clearly fake credentials.
//
// The banned tokens are assembled from fragments so this file does not itself
// reintroduce the strings into the working tree (git grep / code search stays
// clean; the guard still matches the concatenated value at runtime).
const join = (...parts) => parts.join("");
const BANNED = [
  [
    "engagement project name",
    new RegExp(`${join("yue", "wei")}|${join("moo", "dly")}|${join("klc", "xkj")}|${join("qie", "kj")}|${join("kai", "lu")}`, "i"),
  ],
  ["engagement env key", new RegExp(`${join("TAKU", "_APP_", "KEY")}|${join("LOCA", "TION_", "SECRET")}`)],
  ["engagement secret fragment", new RegExp(`${join("ad42", "845e", "8d50")}|${join("nFU9", "pbG8")}|${join("855c", "74a8", "8b8b")}`, "i")],
  ["local user path", /[A-Za-z]:[\\/]{1,2}Users[\\/]/],
  ["internal workspace path", /\u6f0f\u6d1e\u6316\u6398\u5de5\u4f5c\u53f0/],
];

test("no engagement identifiers or local user paths in tracked files", () => {
  const files = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
    .split(/\r?\n/)
    .filter(Boolean);
  const failures = [];
  for (const file of files) {
    let text;
    try {
      text = fs.readFileSync(path.join(ROOT, file), "utf8");
    } catch {
      continue;
    }
    for (const [label, pattern] of BANNED) {
      const match = text.match(pattern);
      if (match) failures.push(`${file}: ${label}: ${match[0].replace(/\n/g, " ")}`);
    }
  }
  assert.deepEqual(failures, [], `sensitive identifiers leaked back into tracked files:\n${failures.join("\n")}`);
});
