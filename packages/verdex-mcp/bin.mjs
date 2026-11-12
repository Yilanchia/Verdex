#!/usr/bin/env node
// Thin stdio entry so `npx -y verdex-mcp` works as advertised.
//
// `npx <name>` resolves an npm *package* by that name, so the MCP server needs
// its own package when the CLI package is `verdex`. This shim simply starts the
// server from the `verdex` dependency; all tools still live in one place.
import { startMcpServer } from "verdex/src/mcp.js";

startMcpServer();
