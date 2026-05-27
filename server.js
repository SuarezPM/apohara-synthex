#!/usr/bin/env node
// apohara-synthex — servidor MCP (FastMCP) que envuelve a brightdata-mcp y le suma
// clasificación, evidencia firmada y monitoreo. Arranca por stdio, igual que el MCP de BD.
import { FastMCP } from "fastmcp";
import { tools } from "./src/tools.js";

const server = new FastMCP({ name: "apohara-synthex", version: "0.1.0" });
for (const tool of tools) server.addTool(tool);

server.start({ transportType: "stdio" });
