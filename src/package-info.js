import { readFileSync } from "node:fs";

// Single source of truth for the package name/version. package.json is always
// shipped with the npm package, so reading it at runtime keeps `verdex
// --version` and the MCP serverInfo in sync with the published artifact.
export function packageInfo() {
  try {
    const text = readFileSync(new URL("../package.json", import.meta.url), "utf8");
    const pkg = JSON.parse(text);
    return {
      name: typeof pkg.name === "string" && pkg.name ? pkg.name : "verdex",
      version: typeof pkg.version === "string" && pkg.version ? pkg.version : "0.0.0",
    };
  } catch {
    return { name: "verdex", version: "0.0.0" };
  }
}
