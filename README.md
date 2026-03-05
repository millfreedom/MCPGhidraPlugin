[![Java CI with Maven](https://github.com/millfreedom/MCPGhidraPlugin/actions/workflows/maven.yml/badge.svg)](https://github.com/millfreedom/MCPGhidraPlugin/actions/workflows/maven.yml)

# MCP Ghidra Plugin

Native Java-only MCP plugin. Written solely by OpenAI's Codex, directed by millfreedom 

## Scope

This project includes only Java MCP-related code:
- MCP HTTP transport (`/mcp`) implemented with `modelcontextprotocol/java-sdk`
- Native MCP tool server (search/functions/datatypes/xrefs/rename/namespace/signature/decompile/disassembly)
- Minimal Ghidra plugin bootstrap (`MCPGhidraPlugin`)
- Minimal local utilities required by the MCP stack (CORS, transaction helper, decompiler/signature helper)

## Build

```bash
mvn -DskipTests package
```

Notes:
- Ghidra jars are pulled from the official GitHub release (no checked-in `lib/*.jar` needed).
- Build is a Maven reactor: `ghidra-bootstrap` runs first, then `mcp-ghidra-plugin`.
- Bootstrap downloads and unpacks Ghidra to `target/ghidra/`.
- If you bump `ghidra.version`, update the release-date property in the root `pom.xml`.

Outputs:
- Plugin JAR: `mcp-ghidra-plugin/target/MCPGhidraPlugin.jar`
- Ghidra extension zip: `mcp-ghidra-plugin/target/MCPGhidraPlugin-1.0.0-SNAPSHOT.zip`

## Install in Ghidra

1. Open Ghidra
2. `File -> Install Extensions`
3. Click `+`
4. Choose `mcp-ghidra-plugin/target/MCPGhidraPlugin-1.0.0-SNAPSHOT.zip`
5. Restart Ghidra and enable the plugin (in CodeBrowser's options)

The server runs on the first available port in `8192..8447` (or `-Dghidra.mcp.port=<port>`).
Root endpoint: `GET /`
MCP endpoint: `POST /mcp`
