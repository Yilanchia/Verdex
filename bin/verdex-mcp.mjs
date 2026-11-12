#!/usr/bin/env node
import { startMcpServer } from "../src/mcp.js";

// `npx -y verdex-mcp` entry point: stdio JSON-RPC only. No argv parsing, no
// network, no file access beyond the tools the host explicitly calls.
startMcpServer();
