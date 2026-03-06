package ua.millfreedom.ghidra.javamcp.mcp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import ua.millfreedom.ghidra.javamcp.util.GhidraFunctionUtil;
import ua.millfreedom.ghidra.javamcp.util.TransactionHelper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpStatelessSyncServer;
import io.modelcontextprotocol.spec.McpSchema;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.math.BigInteger;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Native Java MCP server hosted directly by the Ghidra plugin.
 *
 * Exposes a curated set of MCP tools for searching, navigation, xrefs, and
 * function/datatype manipulation without requiring any Python bridge.
 */
public class NativeMcpServer {

    private static final String MCP_CONTEXT_PATH = "/mcp";
    private static final int DEFAULT_LIMIT = 10;
    private static final int MAX_LIMIT = 2000;
    private static final Gson GSON = new Gson();

    private final PluginTool tool;
    private final int port;
    private final String pluginVersion;
    private final Supplier<Program> currentProgramSupplier;
    private final HttpServerStatelessMcpTransport transport;

    private McpStatelessSyncServer mcpServer;

    public NativeMcpServer(PluginTool tool, int port, String pluginVersion) {
        this(tool, port, pluginVersion, null);
    }

    public NativeMcpServer(PluginTool tool, int port, String pluginVersion, Supplier<Program> currentProgramSupplier) {
        this.tool = tool;
        this.port = port;
        this.pluginVersion = pluginVersion;
        this.currentProgramSupplier = currentProgramSupplier;
        this.transport = new HttpServerStatelessMcpTransport();
    }

    public void register(HttpServer httpServer) {
        httpServer.createContext(MCP_CONTEXT_PATH, transport);
        mcpServer = buildServer();
        Msg.info(this, "Native Java MCP endpoint registered at " + MCP_CONTEXT_PATH + " on port " + port);
    }

    public void close() {
        try {
            if (mcpServer != null) {
                mcpServer.close();
            }
        } catch (Exception e) {
            Msg.warn(this, "Error closing native MCP server", e);
        }
    }

    public String getContextPath() {
        return MCP_CONTEXT_PATH;
    }

    private McpStatelessSyncServer buildServer() {
        return McpServer.sync(transport)
            .serverInfo("GhydraMCP-Java-Only", pluginVersion)
            .capabilities(McpSchema.ServerCapabilities.builder()
                .logging()
                .tools(Boolean.FALSE)
                .resources(Boolean.FALSE, Boolean.FALSE)
                .prompts(Boolean.FALSE)
                .build())
            .instructions(
                "Native Java MCP endpoint for Ghidra reverse engineering. " +
                "Use search tools for functions/datatypes/symbols/xrefs, datatype/symbol/namespace edit tools, " +
                "and function tools for rename, signature/calling-convention, namespace, decompile and disassembly.")
            .toolCall(tool("function_search",
                "Search functions by name/namespace (exact case-insensitive or regex) and by address.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "address": {"type": "string", "description": "Hex address"},
                        "address_mode": {"type": "string", "enum": ["containing", "entry"], "default": "containing"},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::searchFunctions)
            .toolCall(tool("function_list",
                "List functions with optional name/namespace/address filters.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "address": {"type": "string", "description": "Hex address"},
                        "address_mode": {"type": "string", "enum": ["containing", "entry"], "default": "containing"},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::listFunctions)
            .toolCall(tool("datatype_list",
                "List datatypes (optional kind filter).",
                """
                    {
                      "type": "object",
                      "properties": {
                        "kind": {"type": "string", "enum": ["struct", "enum", "union", "array", "pointer", "typedef", "function_def", "bitfield", "other"]},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::listDatatypes)
            .toolCall(tool("datatype_search",
                "Search datatypes by name and full category path using exact case-insensitive or regex matching.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "category": {"type": "string"},
                        "kind": {"type": "string", "enum": ["struct", "enum", "union", "array", "pointer", "typedef", "function_def", "bitfield", "other"]},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::searchDatatypes)
            .toolCall(tool("datatype_get_details",
                "Get detailed information for a datatype by path or name (supports enums, composites and other kinds).",
                """
                    {
                      "type": "object",
                      "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "member_offset": {"type": "integer", "minimum": 0, "default": 0},
                        "member_limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10},
                        "include_members": {"type": "boolean", "default": true}
                      }
                    }
                    """),
                this::getDatatypeDetails)
            .toolCall(tool("datatype_rename",
                "Rename an existing datatype by path or name.",
                """
                    {
                      "type": "object",
                      "required": ["new_name"],
                      "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "new_name": {"type": "string"}
                      }
                    }
                    """),
                this::renameDatatype)
            .toolCall(tool("datatype_field_rename",
                "Rename/update a struct/union field in-place by datatype and field selector.",
                """
                    {
                      "type": "object",
                      "required": ["new_field_name"],
                      "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "field_name": {"type": "string"},
                        "ordinal": {"type": "integer", "minimum": 0},
                        "offset": {"type": "integer", "minimum": 0},
                        "new_field_name": {"type": "string"},
                        "new_comment": {"type": "string"}
                      }
                    }
                    """),
                this::renameDatatypeField)
            .toolCall(tool("category_rename",
                "Rename an existing datatype category by full path.",
                """
                    {
                      "type": "object",
                      "required": ["category", "new_name"],
                      "properties": {
                        "category": {"type": "string", "description": "Existing category path like /A/B/C"},
                        "new_name": {"type": "string"}
                      }
                    }
                    """),
                this::renameCategory)
            .toolCall(tool("category_list",
                "List datatype categories with optional parent scope and recursion.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "parent_category": {"type": "string", "description": "Category path used as list root"},
                        "recursive": {"type": "boolean", "default": true},
                        "include_root": {"type": "boolean", "default": false},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::listCategories)
            .toolCall(tool("category_search",
                "Search categories by name/path/parent using exact case-insensitive or regex matching.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "path": {"type": "string"},
                        "parent_category": {"type": "string"},
                        "include_root": {"type": "boolean", "default": false},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::searchCategories)
            .toolCall(tool("category_get_details",
                "Get details for a category including optional child category/datatype pages.",
                """
                    {
                      "type": "object",
                      "required": ["category"],
                      "properties": {
                        "category": {"type": "string"},
                        "include_subcategories": {"type": "boolean", "default": true},
                        "subcategory_offset": {"type": "integer", "minimum": 0, "default": 0},
                        "subcategory_limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10},
                        "include_datatypes": {"type": "boolean", "default": true},
                        "datatype_offset": {"type": "integer", "minimum": 0, "default": 0},
                        "datatype_limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::getCategoryDetails)
            .toolCall(tool("category_create",
                "Create a datatype category by path.",
                """
                    {
                      "type": "object",
                      "required": ["category"],
                      "properties": {
                        "category": {"type": "string", "description": "Category path like /A/B/C"},
                        "if_exists_ok": {"type": "boolean", "default": false}
                      }
                    }
                    """),
                this::createCategory)
            .toolCall(tool("category_parent_set",
                "Move an existing category under a different parent category.",
                """
                    {
                      "type": "object",
                      "required": ["category", "parent_category"],
                      "properties": {
                        "category": {"type": "string", "description": "Existing category path"},
                        "parent_category": {"type": "string", "description": "Target parent category path"}
                      }
                    }
                    """),
                this::setCategoryParent)
            .toolCall(tool("category_delete",
                "Delete a category (empty-only by default, or recursively).",
                """
                    {
                      "type": "object",
                      "required": ["category"],
                      "properties": {
                        "category": {"type": "string"},
                        "recursive": {"type": "boolean", "default": false},
                        "missing_ok": {"type": "boolean", "default": false}
                      }
                    }
                    """),
                this::deleteCategory)
            .toolCall(tool("enum_member_insert",
                "Insert a new enum member by name/value, with optional comment.",
                """
                    {
                      "type": "object",
                      "required": ["entry_name", "value"],
                      "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "entry_name": {"type": "string"},
                        "value": {"description": "Integer value or hex string (e.g. 0x401)", "oneOf": [{"type": "integer"}, {"type": "string"}]},
                        "comment": {"type": "string"}
                      }
                    }
                    """),
                this::insertEnumMember)
            .toolCall(tool("enum_member_update",
                "Rename/change enum member name/value/comment in-place (without delete+create).",
                """
                    {
                      "type": "object",
                      "required": ["entry_name"],
                      "properties": {
                        "path": {"type": "string"},
                        "name": {"type": "string"},
                        "entry_name": {"type": "string"},
                        "new_name": {"type": "string"},
                        "new_value": {"description": "Integer value or hex string (e.g. 0x401)", "oneOf": [{"type": "integer"}, {"type": "string"}]},
                        "new_comment": {"type": "string"}
                      }
                    }
                    """),
                this::updateEnumMember)
            .toolCall(tool("xref_search",
                "Search xrefs by to/from address and by datatype/field backed addresses.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "to_addr": {"type": "string"},
                        "from_addr": {"type": "string"},
                        "ref_type": {"type": "string", "description": "CALL, READ, WRITE, ..."},
                        "datatype": {"type": "string", "description": "Datatype name/path query for data-backed xrefs"},
                        "field": {"type": "string", "description": "Field name query for composite data-backed xrefs"},
                        "direction": {"type": "string", "enum": ["to", "from", "both"], "default": "both"},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::searchXrefs)
            .toolCall(tool("symbol_search",
                "Search symbols by name/namespace/type/address (exact case-insensitive or regex).",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "address": {"type": "string", "description": "Hex address"},
                        "symbol_type": {"type": "string", "enum": ["label", "code", "library", "namespace", "class", "function", "parameter", "local_var", "global_var", "global"]},
                        "match_mode": {"type": "string", "enum": ["exact_ci", "regex"], "default": "exact_ci"},
                        "regex_ignore_case": {"type": "boolean", "default": true},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 10}
                      }
                    }
                    """),
                this::searchSymbols)
            .toolCall(tool("symbol_rename",
                "Rename a symbol by symbol_id, or by name/address selectors.",
                """
                    {
                      "type": "object",
                      "required": ["new_name"],
                      "properties": {
                        "symbol_id": {"type": "integer"},
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "address": {"type": "string"},
                        "symbol_type": {"type": "string", "enum": ["label", "code", "library", "namespace", "class", "function", "parameter", "local_var", "global_var", "global"]},
                        "new_name": {"type": "string"}
                      }
                    }
                    """),
                this::renameSymbol)
            .toolCall(tool("symbol_namespace_set",
                "Set symbol namespace/class by symbol_id, or by name/address selectors.",
                """
                    {
                      "type": "object",
                      "required": ["namespace"],
                      "properties": {
                        "symbol_id": {"type": "integer"},
                        "name": {"type": "string"},
                        "namespace_query": {"type": "string", "description": "Current namespace filter for symbol resolution"},
                        "address": {"type": "string"},
                        "symbol_type": {"type": "string", "enum": ["label", "code", "library", "namespace", "class", "function", "parameter", "local_var", "global_var", "global"]},
                        "namespace": {"type": "string", "description": "Target namespace path like A::B::C"},
                        "as_class": {"type": "boolean", "default": false, "description": "Create/convert final target namespace segment as class"}
                      }
                    }
                    """),
                this::setSymbolNamespace)
            .toolCall(tool("namespace_rename",
                "Rename an existing namespace/class by full path.",
                """
                    {
                      "type": "object",
                      "required": ["namespace", "new_name"],
                      "properties": {
                        "namespace": {"type": "string", "description": "Existing namespace path like A::B::C"},
                        "new_name": {"type": "string"}
                      }
                    }
                    """),
                this::renameNamespace)
            .toolCall(tool("namespace_parent_set",
                "Move an existing namespace/class under a different parent namespace.",
                """
                    {
                      "type": "object",
                      "required": ["namespace", "parent_namespace"],
                      "properties": {
                        "namespace": {"type": "string", "description": "Existing namespace path like A::B::C"},
                        "parent_namespace": {"type": "string", "description": "Target parent namespace path"},
                        "parent_as_class": {"type": "boolean", "default": false, "description": "Create/convert final parent segment as class"}
                      }
                    }
                    """),
                this::setNamespaceParent)
            .toolCall(tool("function_disassembly_get",
                "Get function disassembly by name or address.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "offset": {"type": "integer", "minimum": 0, "default": 0},
                        "limit": {"type": "integer", "minimum": 0, "default": 10}
                      }
                    }
                    """),
                this::getFunctionDisassembly)
            .toolCall(tool("function_decompile_get",
                "Get function decompilation by name or address.",
                """
                    {
                      "type": "object",
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "show_constants": {"type": "boolean", "default": true},
                        "timeout": {"type": "integer", "minimum": 1, "maximum": 300, "default": 30},
                        "start_line": {"type": "integer", "minimum": 1},
                        "end_line": {"type": "integer", "minimum": 1},
                        "max_lines": {"type": "integer", "minimum": 1}
                      }
                    }
                    """),
                this::getFunctionDecompile)
            .toolCall(tool("function_rename",
                "Rename a function by name or address.",
                """
                    {
                      "type": "object",
                      "required": ["new_name"],
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "new_name": {"type": "string"}
                      }
                    }
                    """),
                this::renameFunction)
            .toolCall(tool("function_calling_convention_set",
                "Set function calling convention by name or address.",
                """
                    {
                      "type": "object",
                      "required": ["calling_convention"],
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "calling_convention": {"type": "string", "description": "Calling convention name (for example: default, unknown, __stdcall, __cdecl)"}
                      }
                    }
                    """),
                this::setFunctionCallingConvention)
            .toolCall(tool("function_signature_set",
                "Set function signature/prototype by name or address.",
                """
                    {
                      "type": "object",
                      "required": ["signature"],
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "signature": {"type": "string", "description": "C-style signature (e.g. int foo(char *x))"},
                        "calling_convention": {"type": "string", "description": "Optional explicit calling convention override"}
                      }
                    }
                    """),
                this::setFunctionSignature)
            .toolCall(tool("function_namespace_set",
                "Set (and create if needed) function namespace by name or address.",
                """
                    {
                      "type": "object",
                      "required": ["namespace"],
                      "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "namespace": {"type": "string", "description": "Path like A::B::C"},
                        "as_class": {"type": "boolean", "default": false, "description": "Create/convert final namespace segment as class"}
                      }
                    }
                    """),
                this::setFunctionNamespace)
            .build();
    }

    private McpSchema.Tool tool(String name, String description, String inputSchema) {
        return McpSchema.Tool.builder()
            .name(name)
            .description(description)
            .inputSchema(McpJsonDefaults.getMapper(), inputSchema)
            .build();
    }

    private McpSchema.CallToolResult searchFunctions(McpTransportContext context, McpSchema.CallToolRequest request) {
        return searchFunctionsInternal(safeArgs(request.arguments()), "function_search");
    }

    private McpSchema.CallToolResult listFunctions(McpTransportContext context, McpSchema.CallToolRequest request) {
        return searchFunctionsInternal(safeArgs(request.arguments()), "function_list");
    }

    private McpSchema.CallToolResult searchFunctionsInternal(Map<String, Object> args, String toolName) {
        try {
            Program program = requireProgram();

            String name = str(args, "name");
            String namespace = str(args, "namespace");
            String addressStr = str(args, "address");
            String addressMode = strOrDefault(args, "address_mode", "containing");
            MatchMode matchMode = matchMode(args);
            boolean regexIgnoreCase = bool(args, "regex_ignore_case", true);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            List<Function> candidates = new ArrayList<>();
            if (notBlank(addressStr)) {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return error("Invalid address: " + addressStr);
                }
                FunctionManager functionManager = program.getFunctionManager();
                Function function;
                if ("entry".equalsIgnoreCase(addressMode)) {
                    function = functionManager.getFunctionAt(address);
                } else {
                    function = functionManager.getFunctionContaining(address);
                    if (function == null) {
                        function = functionManager.getFunctionAt(address);
                    }
                }
                if (function != null) {
                    candidates.add(function);
                }
            } else {
                for (Function function : program.getFunctionManager().getFunctions(true)) {
                    candidates.add(function);
                }
            }

            List<Map<String, Object>> filtered = new ArrayList<>();
            for (Function function : candidates) {
                String functionName = function.getName();
                String functionNamespace = function.getParentNamespace() != null
                    ? function.getParentNamespace().getName(true)
                    : "";

                if (!matches(functionName, name, matchMode, regexIgnoreCase)) {
                    continue;
                }
                if (!matches(functionNamespace, namespace, matchMode, regexIgnoreCase)) {
                    continue;
                }

                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", functionName);
                row.put("namespace", functionNamespace);
                row.put("address", function.getEntryPoint().toString());
                row.put("signature", function.getSignature().getPrototypeString());
                row.put("calling_convention", function.getCallingConventionName());
                filtered.add(row);
            }

            filtered.sort(Comparator
                .comparing((Map<String, Object> m) -> Objects.toString(m.get("name"), ""))
                .thenComparing(m -> Objects.toString(m.get("namespace"), ""))
                .thenComparing(m -> Objects.toString(m.get("address"), "")));

            return paginatedResult(toolName, filtered, offset, limit);
        } catch (Exception e) {
            Msg.error(this, toolName + " failed", e);
            return error(toolName + " failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult listDatatypes(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String kind = str(args, "kind");
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            List<Map<String, Object>> rows = collectDatatypes(program, null, null, kind, MatchMode.EXACT_CI, true);
            return paginatedResult("datatype_list", rows, offset, limit);
        } catch (Exception e) {
            Msg.error(this, "datatype_list failed", e);
            return error("datatype_list failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult searchDatatypes(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String name = str(args, "name");
            String category = str(args, "category");
            String kind = str(args, "kind");
            MatchMode matchMode = matchMode(args);
            boolean regexIgnoreCase = bool(args, "regex_ignore_case", true);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            List<Map<String, Object>> rows = collectDatatypes(program, name, category, kind, matchMode, regexIgnoreCase);
            return paginatedResult("datatype_search", rows, offset, limit);
        } catch (PatternSyntaxException e) {
            return error("Invalid regex: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "datatype_search failed", e);
            return error("datatype_search failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult getDatatypeDetails(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            Resolution<DataType> resolved = resolveDataType(program, args);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }

            boolean includeMembers = bool(args, "include_members", true);
            int memberOffset = nonNegative(intVal(args, "member_offset", 0));
            int memberLimit = boundedLimit(intVal(args, "member_limit", DEFAULT_LIMIT));

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "datatype_get_details");
            result.put("datatype", datatypeDetails(resolved.value(), includeMembers, memberOffset, memberLimit));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "datatype_get_details failed", e);
            return error("datatype_get_details failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameDatatype(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String newName = str(args, "new_name");
            if (!notBlank(newName)) {
                return error("new_name is required");
            }
            String targetName = newName.trim();

            Resolution<DataType> resolved = resolveDataType(program, args);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            DataType dataType = resolved.value();

            String oldName = dataType.getName();
            String oldPath = dataType.getPathName();

            if (!oldName.equals(targetName)) {
                TransactionHelper.executeInTransaction(
                    program,
                    "Rename datatype " + oldPath + " to " + targetName,
                    () -> {
                        dataType.setName(targetName);
                        return null;
                    }
                );
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "datatype_rename");
            result.put("kind", kindOf(dataType));
            result.put("old_name", oldName);
            result.put("new_name", dataType.getName());
            result.put("old_path", oldPath);
            result.put("path", dataType.getPathName());
            result.put("category", dataType.getCategoryPath() != null ? dataType.getCategoryPath().getPath() : "");
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "datatype_rename failed", e);
            return error("datatype_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameDatatypeField(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String newFieldName = str(args, "new_field_name");
            if (!notBlank(newFieldName)) {
                return error("new_field_name is required");
            }

            Resolution<DataType> resolved = resolveDataType(program, args);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            if (!(resolved.value() instanceof Composite composite)) {
                return error("Datatype must be struct or union");
            }

            Resolution<DataTypeComponent> componentResolution = resolveCompositeComponent(composite, args);
            if (!componentResolution.isOk()) {
                return error(componentResolution.error());
            }
            DataTypeComponent component = componentResolution.value();

            String oldFieldName = component.getFieldName();
            boolean hasNewComment = args.containsKey("new_comment");
            String newComment = str(args, "new_comment");

            TransactionHelper.executeInTransaction(
                program,
                "Rename datatype field in " + composite.getPathName(),
                () -> {
                    component.setFieldName(newFieldName);
                    if (hasNewComment) {
                        component.setComment(newComment);
                    }
                    return null;
                }
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "datatype_field_rename");
            result.put("datatype", composite.getPathName());
            result.put("kind", kindOf(composite));
            result.put("ordinal", component.getOrdinal());
            result.put("offset", component.getOffset());
            result.put("old_field_name", oldFieldName);
            result.put("new_field_name", component.getFieldName());
            if (hasNewComment) {
                result.put("new_comment", component.getComment());
            }
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "datatype_field_rename failed", e);
            return error("datatype_field_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameCategory(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String categoryPath = str(args, "category");
            String newName = str(args, "new_name");
            if (!notBlank(categoryPath)) {
                return error("category is required");
            }
            if (!notBlank(newName)) {
                return error("new_name is required");
            }

            Resolution<Category> categoryResolution = resolveCategory(program, categoryPath);
            if (!categoryResolution.isOk()) {
                return error(categoryResolution.error());
            }

            Category category = categoryResolution.value();
            if (category.isRoot()) {
                return error("Root category cannot be renamed");
            }

            String targetName = newName.trim();
            String oldName = category.getName();
            String oldPath = category.getCategoryPath().getPath();
            Category parent = category.getParent();
            if (parent == null) {
                return error("Parent category not found: " + oldPath);
            }

            Category existingWithTargetName = parent.getCategory(targetName);
            if (existingWithTargetName != null && existingWithTargetName != category) {
                return error("Category already exists in parent: " + targetName);
            }

            if (!oldName.equals(targetName)) {
                TransactionHelper.executeInTransaction(
                    program,
                    "Rename category " + oldPath + " to " + targetName,
                    () -> {
                        category.setName(targetName);
                        return null;
                    }
                );
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "category_rename");
            result.put("old_name", oldName);
            result.put("new_name", category.getName());
            result.put("old_category", oldPath);
            result.put("category", category.getCategoryPath().getPath());
            result.put("parent_category", parent.getCategoryPath().getPath());
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "category_rename failed", e);
            return error("category_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult listCategories(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String parentCategoryPath = str(args, "parent_category");
            boolean recursive = bool(args, "recursive", true);
            boolean includeRoot = bool(args, "include_root", false);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            Category root;
            if (notBlank(parentCategoryPath)) {
                Resolution<Category> categoryResolution = resolveCategory(program, parentCategoryPath);
                if (!categoryResolution.isOk()) {
                    return error(categoryResolution.error());
                }
                root = categoryResolution.value();
            } else {
                root = program.getDataTypeManager().getRootCategory();
            }

            List<Category> categories = new ArrayList<>();
            collectCategories(root, recursive, includeRoot, categories);

            List<Map<String, Object>> rows = new ArrayList<>(categories.size());
            for (Category category : categories) {
                rows.add(categoryRow(category));
            }

            rows.sort(Comparator.comparing((Map<String, Object> m) -> Objects.toString(m.get("path"), "")));
            return paginatedResult("category_list", rows, offset, limit);
        } catch (Exception e) {
            Msg.error(this, "category_list failed", e);
            return error("category_list failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult searchCategories(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String nameQuery = str(args, "name");
            String pathQuery = str(args, "path");
            String parentQuery = str(args, "parent_category");
            boolean includeRoot = bool(args, "include_root", false);
            MatchMode matchMode = matchMode(args);
            boolean regexIgnoreCase = bool(args, "regex_ignore_case", true);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            List<Category> categories = new ArrayList<>();
            collectCategories(program.getDataTypeManager().getRootCategory(), true, includeRoot, categories);

            List<Map<String, Object>> rows = new ArrayList<>();
            for (Category category : categories) {
                String name = category.getName();
                String path = category.getCategoryPath().getPath();
                String parentPath = categoryParentPath(category);

                if (!matches(name, nameQuery, matchMode, regexIgnoreCase)) {
                    continue;
                }
                if (!matches(path, pathQuery, matchMode, regexIgnoreCase)) {
                    continue;
                }
                if (!matches(parentPath, parentQuery, matchMode, regexIgnoreCase)) {
                    continue;
                }

                rows.add(categoryRow(category));
            }

            rows.sort(Comparator.comparing((Map<String, Object> m) -> Objects.toString(m.get("path"), "")));
            return paginatedResult("category_search", rows, offset, limit);
        } catch (PatternSyntaxException e) {
            return error("Invalid regex: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "category_search failed", e);
            return error("category_search failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult getCategoryDetails(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String categoryPath = str(args, "category");
            Resolution<Category> categoryResolution = resolveCategory(program, categoryPath);
            if (!categoryResolution.isOk()) {
                return error(categoryResolution.error());
            }

            boolean includeSubcategories = bool(args, "include_subcategories", true);
            int subcategoryOffset = nonNegative(intVal(args, "subcategory_offset", 0));
            int subcategoryLimit = boundedLimit(intVal(args, "subcategory_limit", DEFAULT_LIMIT));
            boolean includeDatatypes = bool(args, "include_datatypes", true);
            int datatypeOffset = nonNegative(intVal(args, "datatype_offset", 0));
            int datatypeLimit = boundedLimit(intVal(args, "datatype_limit", DEFAULT_LIMIT));

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "category_get_details");
            result.put("category", categoryDetails(
                categoryResolution.value(),
                includeSubcategories,
                subcategoryOffset,
                subcategoryLimit,
                includeDatatypes,
                datatypeOffset,
                datatypeLimit));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "category_get_details failed", e);
            return error("category_get_details failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult createCategory(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String categoryPath = str(args, "category");
            boolean ifExistsOk = bool(args, "if_exists_ok", false);
            if (!notBlank(categoryPath)) {
                return error("category is required");
            }

            String normalizedPath = normalizeCategoryPath(categoryPath);
            CategoryPath parsedPath;
            try {
                parsedPath = new CategoryPath(normalizedPath);
            } catch (Exception e) {
                return error("Invalid category path: " + categoryPath);
            }

            DataTypeManager dataTypeManager = program.getDataTypeManager();
            Category existing = dataTypeManager.getCategory(parsedPath);
            if (existing != null) {
                if (!ifExistsOk) {
                    return error("Category already exists: " + normalizedPath);
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("tool", "category_create");
                result.put("created", false);
                result.putAll(categoryRow(existing));
                return ok(result);
            }

            Category created = TransactionHelper.executeInTransaction(
                program,
                "Create category " + normalizedPath,
                () -> dataTypeManager.createCategory(parsedPath)
            );

            if (created == null) {
                return error("Failed to create category: " + normalizedPath);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "category_create");
            result.put("created", true);
            result.putAll(categoryRow(created));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "category_create failed", e);
            return error("category_create failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setCategoryParent(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String categoryPath = str(args, "category");
            String parentPath = str(args, "parent_category");
            if (!notBlank(categoryPath)) {
                return error("category is required");
            }
            if (!notBlank(parentPath)) {
                return error("parent_category is required");
            }

            Resolution<Category> categoryResolution = resolveCategory(program, categoryPath);
            if (!categoryResolution.isOk()) {
                return error(categoryResolution.error());
            }
            Resolution<Category> parentResolution = resolveCategory(program, parentPath);
            if (!parentResolution.isOk()) {
                return error(parentResolution.error());
            }

            Category category = categoryResolution.value();
            Category targetParent = parentResolution.value();
            if (category.isRoot()) {
                return error("Root category cannot be moved");
            }

            CategoryPath sourcePath = category.getCategoryPath();
            CategoryPath targetParentPath = targetParent.getCategoryPath();
            if (sourcePath.equals(targetParentPath)) {
                return error("Category cannot be moved under itself");
            }
            if (sourcePath.isAncestorOrSelf(targetParentPath)) {
                return error("Category cannot be moved under itself or a descendant");
            }

            Category currentParent = category.getParent();
            String oldPath = sourcePath.getPath();
            String oldParentPath = categoryParentPath(category);
            if (currentParent == targetParent) {
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("tool", "category_parent_set");
                result.put("changed", false);
                result.put("name", category.getName());
                result.put("old_category", oldPath);
                result.put("category", category.getCategoryPath().getPath());
                result.put("old_parent_category", oldParentPath);
                result.put("parent_category", targetParentPath.getPath());
                return ok(result);
            }

            Category conflicting = targetParent.getCategory(category.getName());
            if (conflicting != null && conflicting != category) {
                return error("Category already exists in target parent: " + category.getName());
            }

            TransactionHelper.executeInTransaction(
                program,
                "Move category " + oldPath + " under " + targetParentPath.getPath(),
                () -> {
                    targetParent.moveCategory(category, TaskMonitor.DUMMY);
                    return null;
                }
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "category_parent_set");
            result.put("changed", true);
            result.put("name", category.getName());
            result.put("old_category", oldPath);
            result.put("category", category.getCategoryPath().getPath());
            result.put("old_parent_category", oldParentPath);
            result.put("parent_category", categoryParentPath(category));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "category_parent_set failed", e);
            return error("category_parent_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult deleteCategory(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String categoryPath = str(args, "category");
            boolean recursive = bool(args, "recursive", false);
            boolean missingOk = bool(args, "missing_ok", false);
            if (!notBlank(categoryPath)) {
                return error("category is required");
            }

            Resolution<Category> categoryResolution = resolveCategory(program, categoryPath);
            if (!categoryResolution.isOk()) {
                if (missingOk && categoryResolution.error().startsWith("Category not found:")) {
                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("tool", "category_delete");
                    result.put("removed", false);
                    result.put("category", normalizeCategoryPath(categoryPath));
                    return ok(result);
                }
                return error(categoryResolution.error());
            }

            Category category = categoryResolution.value();
            if (category.isRoot()) {
                return error("Root category cannot be deleted");
            }

            Category parent = category.getParent();
            if (parent == null) {
                return error("Parent category not found: " + category.getCategoryPath().getPath());
            }

            String name = category.getName();
            String normalizedPath = category.getCategoryPath().getPath();
            boolean removed = TransactionHelper.executeInTransaction(
                program,
                (recursive ? "Delete category " : "Delete empty category ") + normalizedPath,
                () -> recursive
                    ? parent.removeCategory(name, TaskMonitor.DUMMY)
                    : parent.removeEmptyCategory(name, TaskMonitor.DUMMY)
            );

            if (!removed) {
                if (!recursive) {
                    return error("Category is not empty; use recursive=true to delete: " + normalizedPath);
                }
                return error("Failed to delete category: " + normalizedPath);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "category_delete");
            result.put("removed", true);
            result.put("category", normalizedPath);
            result.put("recursive", recursive);
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "category_delete failed", e);
            return error("category_delete failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult insertEnumMember(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String entryName = str(args, "entry_name");
            if (!notBlank(entryName)) {
                return error("entry_name is required");
            }

            if (!args.containsKey("value")) {
                return error("value is required");
            }
            Long value = parseFlexibleLong(args.get("value"), "value");
            if (value == null) {
                return error("value is required");
            }

            boolean hasComment = args.containsKey("comment");
            String comment = str(args, "comment");

            Resolution<DataType> resolved = resolveDataType(program, args);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            if (!(resolved.value() instanceof Enum enumType)) {
                return error("Datatype must be enum");
            }

            if (enumType.contains(entryName)) {
                return error("Enum member already exists: " + entryName);
            }

            long min = enumType.getMinPossibleValue();
            long max = enumType.getMaxPossibleValue();
            if (value < min || value > max) {
                return error("value out of range [" + min + ", " + max + "] for enum length " + enumType.getLength());
            }

            TransactionHelper.executeInTransaction(
                program,
                "Insert enum member " + entryName + " in " + enumType.getPathName(),
                () -> {
                    if (hasComment) {
                        enumType.add(entryName, value, blankToNull(comment));
                    } else {
                        enumType.add(entryName, value);
                    }
                    return null;
                }
            );

            long insertedValue = enumType.getValue(entryName);
            String insertedComment = enumType.getComment(entryName);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "enum_member_insert");
            result.put("enum", enumType.getPathName());
            result.put("entry_name", entryName);
            result.put("value", insertedValue);
            result.put("value_hex", toHex(insertedValue));
            if (hasComment) {
                result.put("comment", insertedComment);
            }
            return ok(result);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "enum_member_insert failed", e);
            return error("enum_member_insert failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult updateEnumMember(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String entryName = str(args, "entry_name");
            if (!notBlank(entryName)) {
                return error("entry_name is required");
            }

            String newName = str(args, "new_name");
            if (newName != null && newName.isBlank()) {
                return error("new_name cannot be blank");
            }
            boolean hasNewValue = args.containsKey("new_value");
            Long newValue = hasNewValue ? parseFlexibleLong(args.get("new_value")) : null;
            boolean hasNewComment = args.containsKey("new_comment");
            String newComment = str(args, "new_comment");

            if (!notBlank(newName) && !hasNewValue && !hasNewComment) {
                return error("Provide at least one of new_name/new_value/new_comment");
            }

            Resolution<DataType> resolved = resolveDataType(program, args);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            if (!(resolved.value() instanceof Enum enumType)) {
                return error("Datatype must be enum");
            }

            long oldValue;
            try {
                oldValue = enumType.getValue(entryName);
            } catch (NoSuchElementException e) {
                return error("Enum member not found: " + entryName);
            }
            String oldComment = enumType.getComment(entryName);

            if (notBlank(newName) && !entryName.equals(newName) && enumType.contains(newName)) {
                return error("Enum member already exists: " + newName);
            }

            if (hasNewValue && newValue != null) {
                long min = enumType.getMinPossibleValue();
                long max = enumType.getMaxPossibleValue();
                if (newValue < min || newValue > max) {
                    return error("new_value out of range [" + min + ", " + max + "] for enum length " + enumType.getLength());
                }
            }

            TransactionHelper.executeInTransaction(
                program,
                "Update enum member " + entryName + " in " + enumType.getPathName(),
                () -> {
                    updateEnumMemberInPlace(enumType, entryName, newName, newValue, newComment, hasNewComment);
                    return null;
                }
            );

            String finalName = notBlank(newName) ? newName : entryName;
            long finalValue = enumType.getValue(finalName);
            String finalComment = enumType.getComment(finalName);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "enum_member_update");
            result.put("enum", enumType.getPathName());
            result.put("old_name", entryName);
            result.put("new_name", finalName);
            result.put("old_value", oldValue);
            result.put("new_value", finalValue);
            result.put("new_value_hex", toHex(finalValue));
            result.put("old_comment", oldComment);
            if (hasNewComment) {
                result.put("new_comment", finalComment);
            }
            return ok(result);
        } catch (IllegalArgumentException e) {
            return error(e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "enum_member_update failed", e);
            return error("enum_member_update failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult searchSymbols(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String name = str(args, "name");
            String namespace = str(args, "namespace");
            String addressStr = str(args, "address");
            String symbolType = str(args, "symbol_type");
            MatchMode matchMode = matchMode(args);
            boolean regexIgnoreCase = bool(args, "regex_ignore_case", true);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));

            SymbolTable symbolTable = program.getSymbolTable();
            List<Symbol> candidates = new ArrayList<>();
            if (notBlank(addressStr)) {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return error("Invalid address: " + addressStr);
                }
                candidates.addAll(Arrays.asList(symbolTable.getSymbols(address)));
            } else {
                SymbolIterator iterator = symbolTable.getAllSymbols(true);
                while (iterator.hasNext()) {
                    candidates.add(iterator.next());
                }
            }

            List<Map<String, Object>> rows = new ArrayList<>();
            for (Symbol symbol : candidates) {
                String symbolName = symbol.getName();
                String symbolNamespace = symbolNamespace(symbol);
                String symbolTypeKey = symbolTypeKey(symbol.getSymbolType());

                if (!matches(symbolName, name, matchMode, regexIgnoreCase)) {
                    continue;
                }
                if (!matches(symbolNamespace, namespace, matchMode, regexIgnoreCase)) {
                    continue;
                }
                if (!matchesSymbolType(symbolTypeKey, symbolType)) {
                    continue;
                }

                rows.add(symbolRow(symbol));
            }

            rows.sort(Comparator
                .comparing((Map<String, Object> m) -> Objects.toString(m.get("name"), ""))
                .thenComparing(m -> Objects.toString(m.get("namespace"), ""))
                .thenComparing(m -> Objects.toString(m.get("address"), ""))
                .thenComparingLong(m -> ((Number) m.get("symbol_id")).longValue()));

            return paginatedResult("symbol_search", rows, offset, limit);
        } catch (PatternSyntaxException e) {
            return error("Invalid regex: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "symbol_search failed", e);
            return error("symbol_search failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameSymbol(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String newName = str(args, "new_name");
            if (!notBlank(newName)) {
                return error("new_name is required");
            }

            Resolution<Symbol> resolved = resolveSymbol(program, args, "namespace");
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            Symbol symbol = resolved.value();

            String oldName = symbol.getName();
            TransactionHelper.executeInTransaction(program, "Rename symbol " + oldName + " to " + newName, () -> {
                symbol.setName(newName, SourceType.USER_DEFINED);
                return null;
            });

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "symbol_rename");
            result.put("symbol_id", symbol.getID());
            result.put("address", symbol.getAddress().toString());
            result.put("symbol_type", symbolTypeKey(symbol.getSymbolType()));
            result.put("old_name", oldName);
            result.put("new_name", symbol.getName());
            result.put("namespace", symbolNamespace(symbol));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "symbol_rename failed", e);
            return error("symbol_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setSymbolNamespace(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String namespacePath = str(args, "namespace");
            if (!notBlank(namespacePath)) {
                return error("namespace is required");
            }
            boolean asClass = bool(args, "as_class", false);

            Resolution<Symbol> resolved = resolveSymbol(program, args, "namespace_query");
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            Symbol symbol = resolved.value();

            String oldNamespace = symbolNamespace(symbol);
            Namespace targetNamespace = TransactionHelper.executeInTransaction(
                program,
                "Set symbol namespace for " + symbol.getName(),
                () -> {
                    Namespace namespace = getOrCreateNamespace(program, namespacePath, asClass);
                    symbol.setNamespace(namespace);
                    return namespace;
                }
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "symbol_namespace_set");
            result.put("symbol_id", symbol.getID());
            result.put("name", symbol.getName());
            result.put("symbol_type", symbolTypeKey(symbol.getSymbolType()));
            result.put("address", symbol.getAddress().toString());
            result.put("old_namespace", oldNamespace);
            result.put("namespace", targetNamespace != null ? targetNamespace.getName(true) : "");
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "symbol_namespace_set failed", e);
            return error("symbol_namespace_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameNamespace(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String namespacePath = str(args, "namespace");
            String newName = str(args, "new_name");
            if (!notBlank(namespacePath)) {
                return error("namespace is required");
            }
            if (!notBlank(newName)) {
                return error("new_name is required");
            }

            Resolution<Namespace> resolved = resolveNamespace(program, namespacePath);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            Namespace namespace = resolved.value();
            Symbol namespaceSymbol = namespace.getSymbol();
            if (namespaceSymbol == null) {
                return error("Namespace symbol not found for: " + namespacePath);
            }

            String oldName = namespace.getName();
            String oldPath = namespace.getName(true);
            TransactionHelper.executeInTransaction(program, "Rename namespace " + oldPath + " to " + newName, () -> {
                namespaceSymbol.setName(newName, SourceType.USER_DEFINED);
                return null;
            });

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "namespace_rename");
            result.put("symbol_id", namespaceSymbol.getID());
            result.put("old_name", oldName);
            result.put("new_name", namespace.getName());
            result.put("old_namespace", oldPath);
            result.put("namespace", namespace.getName(true));
            result.put("symbol_type", symbolTypeKey(namespaceSymbol.getSymbolType()));
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "namespace_rename failed", e);
            return error("namespace_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setNamespaceParent(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());

            String namespacePath = str(args, "namespace");
            String parentPath = str(args, "parent_namespace");
            boolean parentAsClass = bool(args, "parent_as_class", false);
            if (!notBlank(namespacePath)) {
                return error("namespace is required");
            }
            if (!notBlank(parentPath)) {
                return error("parent_namespace is required");
            }

            Resolution<Namespace> resolved = resolveNamespace(program, namespacePath);
            if (!resolved.isOk()) {
                return error(resolved.error());
            }
            Namespace namespace = resolved.value();
            String oldPath = namespace.getName(true);

            Namespace parent = TransactionHelper.executeInTransaction(
                program,
                "Set namespace parent for " + oldPath,
                () -> {
                    Namespace targetParent = getOrCreateNamespace(program, parentPath, parentAsClass);
                    namespace.setParentNamespace(targetParent);
                    return targetParent;
                }
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "namespace_parent_set");
            result.put("name", namespace.getName());
            result.put("old_namespace", oldPath);
            result.put("namespace", namespace.getName(true));
            result.put("parent_namespace", parent != null ? parent.getName(true) : "");
            Symbol namespaceSymbol = namespace.getSymbol();
            if (namespaceSymbol != null) {
                result.put("symbol_id", namespaceSymbol.getID());
                result.put("symbol_type", symbolTypeKey(namespaceSymbol.getSymbolType()));
            }
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "namespace_parent_set failed", e);
            return error("namespace_parent_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult getFunctionDisassembly(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = nonNegative(intVal(args, "limit", DEFAULT_LIMIT)); // 0 = all when explicitly provided

            List<Map<String, Object>> allInstructions = disassemble(program, function);
            int totalCount = allInstructions.size();
            int startIndex = Math.min(offset, totalCount);
            int endIndex = limit > 0 ? Math.min(startIndex + limit, totalCount) : totalCount;
            List<Map<String, Object>> page = allInstructions.subList(startIndex, endIndex);

            Map<String, Object> functionInfo = new LinkedHashMap<>();
            functionInfo.put("name", function.getName());
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("signature", function.getSignature().getPrototypeString());
            functionInfo.put("calling_convention", function.getCallingConventionName());

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_disassembly_get");
            result.put("function", functionInfo);
            result.put("total_instructions", totalCount);
            result.put("offset", startIndex);
            result.put("limit", limit);
            result.put("returned", page.size());
            result.put("instructions", page);
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_disassembly_get failed", e);
            return error("function_disassembly_get failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult getFunctionDecompile(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            boolean showConstants = bool(args, "show_constants", true);
            int timeout = intVal(args, "timeout", 30);
            Integer startLine = nullableInt(args, "start_line");
            Integer endLine = nullableInt(args, "end_line");
            Integer maxLines = nullableInt(args, "max_lines");

            String decompiled = GhidraFunctionUtil.decompileFunction(function, showConstants, timeout);
            if (decompiled == null) {
                return error("Decompilation failed for function: " + function.getName());
            }

            String[] lines = decompiled.split("\n");
            int totalLines = lines.length;
            String filtered = filterLines(lines, startLine, endLine, maxLines);

            Map<String, Object> functionInfo = new LinkedHashMap<>();
            functionInfo.put("name", function.getName());
            functionInfo.put("address", function.getEntryPoint().toString());
            functionInfo.put("signature", function.getSignature().getPrototypeString());
            functionInfo.put("calling_convention", function.getCallingConventionName());

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_decompile_get");
            result.put("function", functionInfo);
            result.put("decompiled", filtered);
            result.put("total_lines", totalLines);
            if (startLine != null) result.put("start_line", startLine);
            if (endLine != null) result.put("end_line", endLine);
            if (maxLines != null) result.put("max_lines", maxLines);
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_decompile_get failed", e);
            return error("function_decompile_get failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult renameFunction(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String newName = str(args, "new_name");
            if (!notBlank(newName)) {
                return error("new_name is required");
            }

            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            String oldName = function.getName();
            TransactionHelper.executeInTransaction(program, "Rename function " + oldName + " to " + newName, () -> {
                function.setName(newName, SourceType.USER_DEFINED);
                return null;
            });

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_rename");
            result.put("address", function.getEntryPoint().toString());
            result.put("old_name", oldName);
            result.put("new_name", function.getName());
            result.put("namespace", function.getParentNamespace() != null ? function.getParentNamespace().getName(true) : "");
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_rename failed", e);
            return error("function_rename failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setFunctionCallingConvention(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String rawCallingConvention = str(args, "calling_convention");
            String callingConvention = rawCallingConvention != null ? rawCallingConvention.trim() : null;
            if (!notBlank(callingConvention)) {
                return error("calling_convention is required");
            }

            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            boolean success = TransactionHelper.executeInTransaction(
                program,
                "Set function calling convention for " + function.getName(),
                () -> GhidraFunctionUtil.setFunctionCallingConvention(function, callingConvention)
            );
            if (!success) {
                return error(callingConventionErrorMessage(function, callingConvention));
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_calling_convention_set");
            result.put("name", function.getName());
            result.put("address", function.getEntryPoint().toString());
            result.put("calling_convention", function.getCallingConventionName());
            result.put("signature", function.getSignature().getPrototypeString());
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_calling_convention_set failed", e);
            return error("function_calling_convention_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setFunctionSignature(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String signature = str(args, "signature");
            String rawCallingConvention = str(args, "calling_convention");
            String callingConvention = rawCallingConvention != null ? rawCallingConvention.trim() : null;
            if (!notBlank(signature)) {
                return error("signature is required");
            }

            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            boolean success = TransactionHelper.executeInTransaction(
                program,
                "Set function signature for " + function.getName(),
                () -> GhidraFunctionUtil.setFunctionSignature(function, signature, callingConvention)
            );
            if (!success) {
                if (notBlank(callingConvention)) {
                    return error(callingConventionErrorMessage(function, callingConvention));
                }
                return error("Failed to set signature (invalid signature or unsupported calling convention)");
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_signature_set");
            result.put("name", function.getName());
            result.put("address", function.getEntryPoint().toString());
            result.put("signature", function.getSignature().getPrototypeString());
            result.put("calling_convention", function.getCallingConventionName());
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_signature_set failed", e);
            return error("function_signature_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult setFunctionNamespace(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            String namespacePath = str(args, "namespace");
            boolean asClass = bool(args, "as_class", false);
            if (!notBlank(namespacePath)) {
                return error("namespace is required");
            }

            Function function = resolveFunction(program, args);
            if (function == null) {
                return error("Function not found (provide valid name or address)");
            }

            Namespace targetNamespace = TransactionHelper.executeInTransaction(
                program,
                "Set function namespace for " + function.getName(),
                () -> {
                    Namespace namespace = getOrCreateNamespace(program, namespacePath, asClass);
                    function.setParentNamespace(namespace);
                    return namespace;
                }
            );

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("tool", "function_namespace_set");
            result.put("name", function.getName());
            result.put("address", function.getEntryPoint().toString());
            result.put("namespace", targetNamespace != null ? targetNamespace.getName(true) : "");
            return ok(result);
        } catch (Exception e) {
            Msg.error(this, "function_namespace_set failed", e);
            return error("function_namespace_set failed: " + e.getMessage());
        }
    }

    private McpSchema.CallToolResult searchXrefs(McpTransportContext context, McpSchema.CallToolRequest request) {
        try {
            Program program = requireProgram();
            Map<String, Object> args = safeArgs(request.arguments());
            MatchMode matchMode = matchMode(args);
            boolean regexIgnoreCase = bool(args, "regex_ignore_case", true);
            int offset = nonNegative(intVal(args, "offset", 0));
            int limit = boundedLimit(intVal(args, "limit", DEFAULT_LIMIT));
            String direction = strOrDefault(args, "direction", "both").toLowerCase(Locale.ROOT);

            String toAddrStr = str(args, "to_addr");
            String fromAddrStr = str(args, "from_addr");
            String refTypeFilter = str(args, "ref_type");
            String datatypeQuery = str(args, "datatype");
            String fieldQuery = str(args, "field");

            Set<Address> toTargets = new LinkedHashSet<>();
            Set<Address> fromSources = new LinkedHashSet<>();

            if (notBlank(toAddrStr)) {
                Address toAddress = parseAddress(program, toAddrStr);
                if (toAddress == null) {
                    return error("Invalid to_addr: " + toAddrStr);
                }
                toTargets.add(toAddress);
            }
            if (notBlank(fromAddrStr)) {
                Address fromAddress = parseAddress(program, fromAddrStr);
                if (fromAddress == null) {
                    return error("Invalid from_addr: " + fromAddrStr);
                }
                fromSources.add(fromAddress);
            }

            if (notBlank(datatypeQuery) || notBlank(fieldQuery)) {
                Set<Address> dataAddresses = findDataAddresses(program, datatypeQuery, fieldQuery, matchMode, regexIgnoreCase);
                if (dataAddresses.isEmpty()) {
                    Map<String, Object> empty = new LinkedHashMap<>();
                    empty.put("tool", "xref_search");
                    empty.put("size", 0);
                    empty.put("offset", 0);
                    empty.put("limit", limit);
                    empty.put("references", Collections.emptyList());
                    return ok(empty);
                }

                if ("to".equals(direction) || "both".equals(direction)) {
                    toTargets.addAll(dataAddresses);
                }
                if ("from".equals(direction) || "both".equals(direction)) {
                    fromSources.addAll(dataAddresses);
                }
            }

            if (toTargets.isEmpty() && fromSources.isEmpty()) {
                return error("Provide to_addr/from_addr and/or datatype/field search criteria");
            }

            if (!Arrays.asList("to", "from", "both").contains(direction)) {
                return error("direction must be one of: to, from, both");
            }

            List<Map<String, Object>> refs = new ArrayList<>();
            Set<String> dedupe = new LinkedHashSet<>();
            ReferenceManager referenceManager = program.getReferenceManager();

            if ("to".equals(direction) || "both".equals(direction)) {
                for (Address target : toTargets) {
                    Iterator<Reference> iterator = referenceManager.getReferencesTo(target);
                    while (iterator.hasNext()) {
                        Reference ref = iterator.next();
                        if (!matchesRefType(ref, refTypeFilter)) {
                            continue;
                        }
                        String key = ref.getFromAddress() + "->" + ref.getToAddress() + ":" + ref.getReferenceType().getName();
                        if (dedupe.add(key)) {
                            refs.add(referenceRow(program, ref, "to"));
                        }
                    }
                }
            }

            if ("from".equals(direction) || "both".equals(direction)) {
                for (Address source : fromSources) {
                    Reference[] fromReferences = referenceManager.getReferencesFrom(source);
                    for (Reference ref : fromReferences) {
                        if (!matchesRefType(ref, refTypeFilter)) {
                            continue;
                        }
                        String key = ref.getFromAddress() + "->" + ref.getToAddress() + ":" + ref.getReferenceType().getName();
                        if (dedupe.add(key)) {
                            refs.add(referenceRow(program, ref, "from"));
                        }
                    }
                }
            }

            refs.sort(Comparator
                .comparing((Map<String, Object> m) -> Objects.toString(m.get("from_addr"), ""))
                .thenComparing(m -> Objects.toString(m.get("to_addr"), ""))
                .thenComparing(m -> Objects.toString(m.get("ref_type"), "")));

            return paginatedResult("xref_search", refs, offset, limit);
        } catch (PatternSyntaxException e) {
            return error("Invalid regex: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "xref_search failed", e);
            return error("xref_search failed: " + e.getMessage());
        }
    }

    private List<Map<String, Object>> collectDatatypes(
        Program program,
        String nameQuery,
        String categoryQuery,
        String kindFilter,
        MatchMode matchMode,
        boolean regexIgnoreCase
    ) {
        DataTypeManager dataTypeManager = program.getDataTypeManager();
        List<Map<String, Object>> rows = new ArrayList<>();

        Iterator<DataType> iterator = dataTypeManager.getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            String kind = kindOf(dataType);
            if (kindFilter != null && !kindFilter.isBlank() && !kindFilter.equalsIgnoreCase(kind)) {
                continue;
            }

            String name = dataType.getName();
            String category = dataType.getCategoryPath() != null ? dataType.getCategoryPath().getPath() : "";
            if (!matches(name, nameQuery, matchMode, regexIgnoreCase)) {
                continue;
            }
            if (!matches(category, categoryQuery, matchMode, regexIgnoreCase)) {
                continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", dataType.getName());
            row.put("display_name", dataType.getDisplayName());
            row.put("path", dataType.getPathName());
            row.put("category", category);
            row.put("kind", kind);
            row.put("length", dataType.getLength());

            if (dataType instanceof Structure structure) {
                row.put("num_components", structure.getNumComponents());
            } else if (dataType instanceof Union union) {
                row.put("num_components", union.getNumComponents());
            } else if (dataType instanceof Enum enumType) {
                row.put("num_values", enumType.getCount());
            }

            rows.add(row);
        }

        rows.sort(Comparator
            .comparing((Map<String, Object> m) -> Objects.toString(m.get("name"), ""))
            .thenComparing(m -> Objects.toString(m.get("category"), "")));
        return rows;
    }

    private Map<String, Object> datatypeDetails(DataType dataType, boolean includeMembers, int memberOffset, int memberLimit) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", dataType.getName());
        row.put("display_name", dataType.getDisplayName());
        row.put("path", dataType.getPathName());
        row.put("category", dataType.getCategoryPath() != null ? dataType.getCategoryPath().getPath() : "");
        row.put("kind", kindOf(dataType));
        row.put("java_type", dataType.getClass().getName());
        row.put("length", dataType.getLength());
        row.put("aligned_length", dataType.getAlignedLength());
        row.put("alignment", dataType.getAlignment());
        row.put("description", dataType.getDescription());
        row.put("default_label_prefix", dataType.getDefaultLabelPrefix());
        row.put("is_zero_length", dataType.isZeroLength());
        row.put("is_not_yet_defined", dataType.isNotYetDefined());
        row.put("has_language_dependent_length", dataType.hasLanguageDependantLength());
        row.put("parent_count", dataType.getParents() != null ? dataType.getParents().size() : 0);

        if (dataType instanceof Enum enumType) {
            addEnumDetails(row, enumType, includeMembers, memberOffset, memberLimit);
        }
        if (dataType instanceof Composite composite) {
            addCompositeDetails(row, composite, includeMembers, memberOffset, memberLimit);
        }
        if (dataType instanceof Array arrayType) {
            row.put("num_elements", arrayType.getNumElements());
            row.put("element_length", arrayType.getElementLength());
            row.put("element_type", dataTypeRef(arrayType.getDataType()));
        }
        if (dataType instanceof Pointer pointerType) {
            row.put("points_to", dataTypeRef(pointerType.getDataType()));
        }
        if (dataType instanceof TypeDef typeDef) {
            row.put("is_auto_named", typeDef.isAutoNamed());
            row.put("base_data_type", dataTypeRef(typeDef.getBaseDataType()));
            row.put("data_type", dataTypeRef(typeDef.getDataType()));
        }
        if (dataType instanceof BitFieldDataType bitField) {
            row.put("bit_size", bitField.getBitSize());
            row.put("declared_bit_size", bitField.getDeclaredBitSize());
            row.put("bit_offset", bitField.getBitOffset());
            row.put("storage_size", bitField.getStorageSize());
            row.put("base_data_type", dataTypeRef(bitField.getBaseDataType()));
        }
        if (dataType instanceof FunctionDefinition functionDefinition) {
            addFunctionDefinitionDetails(row, functionDefinition, includeMembers, memberOffset, memberLimit);
        }

        return row;
    }

    private void addEnumDetails(
        Map<String, Object> out,
        Enum enumType,
        boolean includeMembers,
        int memberOffset,
        int memberLimit
    ) {
        out.put("num_values", enumType.getCount());
        out.put("is_signed", enumType.isSigned());
        out.put("signed_state", String.valueOf(enumType.getSignedState()));
        out.put("min_possible_value", enumType.getMinPossibleValue());
        out.put("max_possible_value", enumType.getMaxPossibleValue());
        out.put("minimum_possible_length", enumType.getMinimumPossibleLength());

        if (!includeMembers) {
            return;
        }

        String[] names = enumType.getNames();
        List<Map<String, Object>> entries = new ArrayList<>();
        for (String name : names) {
            long value = enumType.getValue(name);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", name);
            entry.put("value", value);
            entry.put("value_hex", toHex(value));
            entry.put("comment", enumType.getComment(name));
            entries.add(entry);
        }

        int start = Math.min(memberOffset, entries.size());
        int end = Math.min(start + memberLimit, entries.size());
        out.put("member_offset", start);
        out.put("member_limit", memberLimit);
        out.put("member_total", entries.size());
        out.put("members", entries.subList(start, end));
    }

    private void addCompositeDetails(
        Map<String, Object> out,
        Composite composite,
        boolean includeMembers,
        int memberOffset,
        int memberLimit
    ) {
        out.put("num_components", composite.getNumComponents());
        out.put("num_defined_components", composite.getNumDefinedComponents());
        out.put("packing_type", String.valueOf(composite.getPackingType()));
        out.put("alignment_type", String.valueOf(composite.getAlignmentType()));
        out.put("explicit_packing_value", composite.getExplicitPackingValue());
        out.put("explicit_minimum_alignment", composite.getExplicitMinimumAlignment());

        if (!includeMembers) {
            return;
        }

        DataTypeComponent[] components = composite.getComponents();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (DataTypeComponent component : components) {
            rows.add(componentRow(component));
        }

        int start = Math.min(memberOffset, rows.size());
        int end = Math.min(start + memberLimit, rows.size());
        out.put("member_offset", start);
        out.put("member_limit", memberLimit);
        out.put("member_total", rows.size());
        out.put("members", rows.subList(start, end));
    }

    private void addFunctionDefinitionDetails(
        Map<String, Object> out,
        FunctionDefinition functionDefinition,
        boolean includeMembers,
        int memberOffset,
        int memberLimit
    ) {
        out.put("prototype", functionDefinition.getPrototypeString());
        out.put("calling_convention", functionDefinition.getCallingConventionName());
        out.put("has_var_args", functionDefinition.hasVarArgs());
        out.put("has_no_return", functionDefinition.hasNoReturn());
        out.put("return_type", dataTypeRef(functionDefinition.getReturnType()));
        out.put("comment", functionDefinition.getComment());

        if (!includeMembers) {
            return;
        }

        ParameterDefinition[] arguments = functionDefinition.getArguments();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (ParameterDefinition argument : arguments) {
            Map<String, Object> parameter = new LinkedHashMap<>();
            parameter.put("ordinal", argument.getOrdinal());
            parameter.put("name", argument.getName());
            parameter.put("length", argument.getLength());
            parameter.put("comment", argument.getComment());
            parameter.put("data_type", dataTypeRef(argument.getDataType()));
            rows.add(parameter);
        }

        int start = Math.min(memberOffset, rows.size());
        int end = Math.min(start + memberLimit, rows.size());
        out.put("member_offset", start);
        out.put("member_limit", memberLimit);
        out.put("member_total", rows.size());
        out.put("members", rows.subList(start, end));
    }

    private Map<String, Object> dataTypeRef(DataType dataType) {
        if (dataType == null) {
            return Collections.emptyMap();
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", dataType.getName());
        row.put("path", dataType.getPathName());
        row.put("kind", kindOf(dataType));
        row.put("length", dataType.getLength());
        return row;
    }

    private Map<String, Object> componentRow(DataTypeComponent component) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ordinal", component.getOrdinal());
        row.put("offset", component.getOffset());
        row.put("end_offset", component.getEndOffset());
        row.put("length", component.getLength());
        row.put("field_name", component.getFieldName());
        row.put("default_field_name", component.getDefaultFieldName());
        row.put("comment", component.getComment());
        row.put("is_bitfield", component.isBitFieldComponent());
        row.put("is_zero_bitfield", component.isZeroBitFieldComponent());
        row.put("is_undefined", component.isUndefined());
        row.put("data_type", dataTypeRef(component.getDataType()));
        return row;
    }

    private Resolution<DataType> resolveDataType(Program program, Map<String, Object> args) {
        String path = str(args, "path");
        String name = str(args, "name");
        DataTypeManager dataTypeManager = program.getDataTypeManager();

        if (!notBlank(path) && !notBlank(name)) {
            return Resolution.error("Provide datatype path or name");
        }

        if (notBlank(path)) {
            DataType byPath = dataTypeManager.getDataType(path);
            if (byPath != null) {
                return Resolution.ok(byPath);
            }
            if (!notBlank(name)) {
                return Resolution.error("Datatype not found for path: " + path);
            }
        }

        List<DataType> exactMatches = new ArrayList<>();
        List<DataType> ciMatches = new ArrayList<>();
        Iterator<DataType> iterator = dataTypeManager.getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            if (!notBlank(name)) {
                continue;
            }
            if (dataType.getName().equals(name)) {
                exactMatches.add(dataType);
            } else if (dataType.getName().equalsIgnoreCase(name)) {
                ciMatches.add(dataType);
            }
        }

        if (exactMatches.size() == 1) {
            return Resolution.ok(exactMatches.get(0));
        }
        if (exactMatches.size() > 1) {
            return Resolution.error("Multiple datatypes match name '" + name + "': " + summarizeDataTypes(exactMatches));
        }
        if (ciMatches.size() == 1) {
            return Resolution.ok(ciMatches.get(0));
        }
        if (ciMatches.size() > 1) {
            return Resolution.error("Multiple datatypes match name (case-insensitive) '" + name + "': " + summarizeDataTypes(ciMatches));
        }

        return Resolution.error("Datatype not found for name: " + name);
    }

    private String summarizeDataTypes(List<DataType> dataTypes) {
        List<String> paths = new ArrayList<>();
        for (int i = 0; i < dataTypes.size() && i < 5; i++) {
            paths.add(dataTypes.get(i).getPathName());
        }
        if (dataTypes.size() > 5) {
            paths.add("...+" + (dataTypes.size() - 5) + " more");
        }
        return String.join(", ", paths);
    }

    private void collectCategories(Category root, boolean recursive, boolean includeRoot, List<Category> out) {
        if (root == null || out == null) {
            return;
        }
        if (includeRoot) {
            out.add(root);
        }

        Category[] children = root.getCategories();
        if (children == null) {
            return;
        }

        for (Category child : children) {
            if (child == null) {
                continue;
            }
            out.add(child);
            if (recursive) {
                collectCategories(child, true, false, out);
            }
        }
    }

    private String categoryParentPath(Category category) {
        Category parent = category != null ? category.getParent() : null;
        if (parent == null || parent.getCategoryPath() == null) {
            return "";
        }
        return parent.getCategoryPath().getPath();
    }

    private Map<String, Object> categoryRow(Category category) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", category != null ? category.getName() : "");
        row.put("path", category != null && category.getCategoryPath() != null ? category.getCategoryPath().getPath() : "");
        row.put("parent_category", categoryParentPath(category));
        row.put("is_root", category != null && category.isRoot());
        row.put("id", category != null ? category.getID() : -1L);
        row.put("num_subcategories", category != null && category.getCategories() != null ? category.getCategories().length : 0);
        row.put("num_datatypes", category != null && category.getDataTypes() != null ? category.getDataTypes().length : 0);
        return row;
    }

    private Map<String, Object> categoryDetails(
        Category category,
        boolean includeSubcategories,
        int subcategoryOffset,
        int subcategoryLimit,
        boolean includeDatatypes,
        int datatypeOffset,
        int datatypeLimit
    ) {
        Map<String, Object> row = categoryRow(category);

        if (includeSubcategories) {
            List<Map<String, Object>> subcategories = new ArrayList<>();
            Category[] children = category.getCategories();
            if (children != null) {
                for (Category child : children) {
                    if (child != null) {
                        subcategories.add(categoryRow(child));
                    }
                }
            }

            subcategories.sort(Comparator.comparing((Map<String, Object> m) -> Objects.toString(m.get("path"), "")));
            int subStart = Math.min(subcategoryOffset, subcategories.size());
            int subEnd = Math.min(subStart + subcategoryLimit, subcategories.size());
            row.put("subcategory_offset", subStart);
            row.put("subcategory_limit", subcategoryLimit);
            row.put("subcategory_total", subcategories.size());
            row.put("subcategories", subcategories.subList(subStart, subEnd));
        }

        if (includeDatatypes) {
            List<Map<String, Object>> datatypes = new ArrayList<>();
            DataType[] categoryDatatypes = category.getDataTypes();
            if (categoryDatatypes != null) {
                for (DataType dataType : categoryDatatypes) {
                    if (dataType == null) {
                        continue;
                    }
                    Map<String, Object> dataTypeRow = new LinkedHashMap<>(dataTypeRef(dataType));
                    dataTypeRow.put("display_name", dataType.getDisplayName());
                    datatypes.add(dataTypeRow);
                }
            }

            datatypes.sort(Comparator
                .comparing((Map<String, Object> m) -> Objects.toString(m.get("name"), ""))
                .thenComparing(m -> Objects.toString(m.get("path"), "")));
            int dtStart = Math.min(datatypeOffset, datatypes.size());
            int dtEnd = Math.min(dtStart + datatypeLimit, datatypes.size());
            row.put("datatype_offset", dtStart);
            row.put("datatype_limit", datatypeLimit);
            row.put("datatype_total", datatypes.size());
            row.put("datatypes", datatypes.subList(dtStart, dtEnd));
        }

        return row;
    }

    private Resolution<Category> resolveCategory(Program program, String categoryPath) {
        if (!notBlank(categoryPath)) {
            return Resolution.error("category is required");
        }

        String normalizedPath = normalizeCategoryPath(categoryPath);
        CategoryPath parsedPath;
        try {
            parsedPath = new CategoryPath(normalizedPath);
        } catch (Exception e) {
            return Resolution.error("Invalid category path: " + categoryPath);
        }

        Category category = program.getDataTypeManager().getCategory(parsedPath);
        if (category == null) {
            return Resolution.error("Category not found: " + normalizedPath);
        }
        return Resolution.ok(category);
    }

    private Resolution<DataTypeComponent> resolveCompositeComponent(Composite composite, Map<String, Object> args) {
        Integer ordinal = nullableInt(args, "ordinal");
        Integer offset = nullableInt(args, "offset");
        String fieldName = str(args, "field_name");

        if (ordinal == null && offset == null && !notBlank(fieldName)) {
            return Resolution.error("Provide one selector: ordinal, offset or field_name");
        }

        List<DataTypeComponent> candidates = new ArrayList<>();
        for (DataTypeComponent component : composite.getComponents()) {
            if (component == null) {
                continue;
            }
            if (ordinal != null && component.getOrdinal() != ordinal) {
                continue;
            }
            if (offset != null && component.getOffset() != offset) {
                continue;
            }
            if (notBlank(fieldName)) {
                String current = component.getFieldName();
                if (current == null || !current.equalsIgnoreCase(fieldName)) {
                    continue;
                }
            }
            candidates.add(component);
        }

        if (candidates.isEmpty()) {
            return Resolution.error("Datatype component not found");
        }
        if (candidates.size() > 1) {
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < candidates.size() && i < 8; i++) {
                DataTypeComponent c = candidates.get(i);
                ids.add("ordinal=" + c.getOrdinal() + "/offset=" + c.getOffset());
            }
            if (candidates.size() > 8) {
                ids.add("...+" + (candidates.size() - 8) + " more");
            }
            return Resolution.error("Datatype component selector is ambiguous: " + String.join(", ", ids));
        }

        return Resolution.ok(candidates.get(0));
    }

    private Resolution<Symbol> resolveSymbol(Program program, Map<String, Object> args, String namespaceKey) {
        SymbolTable symbolTable = program.getSymbolTable();
        Long symbolId = nullableLong(args, "symbol_id");
        String name = str(args, "name");
        String namespaceFilter = str(args, namespaceKey);
        String addressStr = str(args, "address");
        String symbolType = str(args, "symbol_type");

        if (symbolId != null) {
            Symbol symbol = symbolTable.getSymbol(symbolId);
            if (symbol == null) {
                return Resolution.error("Symbol not found for symbol_id: " + symbolId);
            }
            if (notBlank(name) && !symbol.getName().equalsIgnoreCase(name)) {
                return Resolution.error("symbol_id resolves to '" + symbol.getName() + "', not '" + name + "'");
            }
            if (notBlank(namespaceFilter) &&
                !normalizeNamespacePath(symbolNamespace(symbol)).equalsIgnoreCase(normalizeNamespacePath(namespaceFilter))) {
                return Resolution.error("symbol_id namespace mismatch");
            }
            if (!matchesSymbolType(symbolTypeKey(symbol.getSymbolType()), symbolType)) {
                return Resolution.error("symbol_id symbol_type mismatch");
            }
            return Resolution.ok(symbol);
        }

        if (!notBlank(addressStr) && !notBlank(name)) {
            return Resolution.error("Provide symbol_id or address/name selectors");
        }

        List<Symbol> candidates = new ArrayList<>();
        if (notBlank(addressStr)) {
            Address address = parseAddress(program, addressStr);
            if (address == null) {
                return Resolution.error("Invalid address: " + addressStr);
            }
            candidates.addAll(Arrays.asList(symbolTable.getSymbols(address)));
        } else if (notBlank(name) && notBlank(namespaceFilter)) {
            Resolution<Namespace> namespaceResolution = resolveNamespace(program, namespaceFilter);
            if (!namespaceResolution.isOk()) {
                return Resolution.error(namespaceResolution.error());
            }
            candidates.addAll(symbolTable.getSymbols(name, namespaceResolution.value()));
        } else if (notBlank(name)) {
            SymbolIterator iterator = symbolTable.getSymbols(name);
            while (iterator.hasNext()) {
                candidates.add(iterator.next());
            }
        }

        List<Symbol> filtered = new ArrayList<>();
        for (Symbol symbol : candidates) {
            if (notBlank(name) && !symbol.getName().equalsIgnoreCase(name)) {
                continue;
            }
            if (notBlank(namespaceFilter) &&
                !normalizeNamespacePath(symbolNamespace(symbol)).equalsIgnoreCase(normalizeNamespacePath(namespaceFilter))) {
                continue;
            }
            if (!matchesSymbolType(symbolTypeKey(symbol.getSymbolType()), symbolType)) {
                continue;
            }
            filtered.add(symbol);
        }

        if (filtered.isEmpty()) {
            return Resolution.error("Symbol not found");
        }
        if (filtered.size() > 1) {
            List<String> ids = new ArrayList<>();
            for (int i = 0; i < filtered.size() && i < 8; i++) {
                Symbol symbol = filtered.get(i);
                ids.add(symbol.getID() + ":" + symbol.getName(true) + "@" + symbol.getAddress());
            }
            if (filtered.size() > 8) {
                ids.add("...+" + (filtered.size() - 8) + " more");
            }
            return Resolution.error("Symbol selector is ambiguous: " + String.join(", ", ids));
        }
        return Resolution.ok(filtered.get(0));
    }

    private Map<String, Object> symbolRow(Symbol symbol) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("symbol_id", symbol.getID());
        row.put("name", symbol.getName());
        row.put("full_name", symbol.getName(true));
        row.put("namespace", symbolNamespace(symbol));
        row.put("address", symbol.getAddress().toString());
        row.put("symbol_type", symbolTypeKey(symbol.getSymbolType()));
        row.put("source", symbol.getSource() != null ? symbol.getSource().toString() : "");
        row.put("is_primary", symbol.isPrimary());
        row.put("is_external", symbol.isExternal());
        row.put("is_dynamic", symbol.isDynamic());
        Symbol parent = symbol.getParentSymbol();
        if (parent != null) {
            row.put("parent_symbol_id", parent.getID());
            row.put("parent_name", parent.getName(true));
        }
        return row;
    }

    private String symbolNamespace(Symbol symbol) {
        Namespace parent = symbol != null ? symbol.getParentNamespace() : null;
        return parent != null ? parent.getName(true) : "";
    }

    private String symbolTypeKey(SymbolType symbolType) {
        if (symbolType == null) {
            return "unknown";
        }
        String normalized = symbolType.toString().trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_");
        if ("local_variable".equals(normalized)) return "local_var";
        if ("global_variable".equals(normalized)) return "global_var";
        return normalized;
    }

    private boolean matchesSymbolType(String symbolTypeKey, String query) {
        if (!notBlank(query)) {
            return true;
        }
        String normalized = query.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_");
        if ("local_variable".equals(normalized)) normalized = "local_var";
        if ("global_variable".equals(normalized)) normalized = "global_var";
        return symbolTypeKey.equals(normalized);
    }

    private Resolution<Namespace> resolveNamespace(Program program, String namespacePath) {
        if (!notBlank(namespacePath)) {
            return Resolution.ok(program.getGlobalNamespace());
        }
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace current = program.getGlobalNamespace();
        String[] parts = normalizeNamespacePath(namespacePath).split("::");
        for (String rawPart : parts) {
            String part = rawPart.trim();
            if (part.isEmpty()) {
                continue;
            }
            Namespace next = symbolTable.getNamespace(part, current);
            if (next == null) {
                return Resolution.error("Namespace not found: " + namespacePath);
            }
            current = next;
        }
        return Resolution.ok(current);
    }

    private void updateEnumMemberInPlace(
        Enum enumType,
        String entryName,
        String newName,
        Long newValue,
        String newComment,
        boolean hasNewComment
    ) throws Exception {
        if (!"ghidra.program.database.data.EnumDB".equals(enumType.getClass().getName())) {
            throw new IllegalArgumentException(
                "In-place enum member updates are supported only for program-backed EnumDB types; got " +
                    enumType.getClass().getName()
            );
        }

        Object enumDb = enumType;
        Object lock = getFieldValue(enumDb, "lock");
        invokeCompatibleMethod(lock, "acquire");
        try {
            invokeCompatibleMethod(enumDb, "checkDeleted");
            invokeCompatibleMethod(enumDb, "initializeIfNeeded");

            long enumKey = ((Number) getFieldValue(enumDb, "key")).longValue();
            Object valueAdapter = getFieldValue(enumDb, "valueAdapter");
            Object[] valueIds = toObjectArray(invokeCompatibleMethod(valueAdapter, "getValueIdsInEnum", enumKey));

            Object targetRecord = null;
            for (Object valueId : valueIds) {
                long recordKey = ((Number) invokeCompatibleMethod(valueId, "getLongValue")).longValue();
                Object record = invokeCompatibleMethod(valueAdapter, "getRecord", recordKey);
                String recordName = (String) invokeCompatibleMethod(record, "getString", 0);
                if (entryName.equals(recordName)) {
                    targetRecord = record;
                    break;
                }
            }
            if (targetRecord == null) {
                throw new IllegalArgumentException("Enum member not found: " + entryName);
            }

            if (notBlank(newName) && !entryName.equals(newName)) {
                invokeCompatibleMethod(targetRecord, "setString", 0, newName);
            }
            if (newValue != null) {
                invokeCompatibleMethod(targetRecord, "setLongValue", 1, newValue.longValue());
            }
            if (hasNewComment) {
                invokeCompatibleMethod(targetRecord, "setString", 3, blankToNull(newComment));
            }

            invokeCompatibleMethod(valueAdapter, "updateRecord", targetRecord);

            Object adapter = getFieldValue(enumDb, "adapter");
            Object enumRecord = getFieldValue(enumDb, "record");
            invokeCompatibleMethod(adapter, "updateRecord", enumRecord, true);

            invokeCompatibleMethod(enumDb, "refresh");

            Object dataMgr = getFieldValue(enumDb, "dataMgr");
            invokeCompatibleMethod(dataMgr, "dataTypeChanged", enumDb, false);
        } finally {
            invokeCompatibleMethod(lock, "release");
        }
    }

    private Object getFieldValue(Object target, String fieldName) throws Exception {
        Class<?> cls = target.getClass();
        while (cls != null) {
            try {
                Field field = cls.getDeclaredField(fieldName);
                if (!field.canAccess(target)) {
                    field.setAccessible(true);
                }
                return field.get(target);
            } catch (NoSuchFieldException e) {
                cls = cls.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    private Object invokeCompatibleMethod(Object target, String methodName, Object... args) throws Exception {
        Method method = findCompatibleMethod(target.getClass(), methodName, args);
        if (method == null) {
            throw new NoSuchMethodException(
                "Method not found: " + methodName + " on " + target.getClass().getName() + " with " + args.length + " args"
            );
        }
        if (!method.canAccess(target)) {
            method.setAccessible(true);
        }

        Object[] coerced = coerceArguments(method.getParameterTypes(), args);
        try {
            return method.invoke(target, coerced);
        } catch (ReflectiveOperationException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw e;
        }
    }

    private Method findCompatibleMethod(Class<?> type, String name, Object[] args) {
        Class<?> cls = type;
        while (cls != null) {
            Method[] methods = cls.getDeclaredMethods();
            for (Method method : methods) {
                if (!method.getName().equals(name)) {
                    continue;
                }
                if (method.getParameterCount() != args.length) {
                    continue;
                }
                if (parametersCompatible(method.getParameterTypes(), args)) {
                    return method;
                }
            }
            cls = cls.getSuperclass();
        }
        return null;
    }

    private boolean parametersCompatible(Class<?>[] parameterTypes, Object[] args) {
        for (int i = 0; i < parameterTypes.length; i++) {
            if (!isParameterCompatible(parameterTypes[i], args[i])) {
                return false;
            }
        }
        return true;
    }

    private boolean isParameterCompatible(Class<?> parameterType, Object arg) {
        if (arg == null) {
            return !parameterType.isPrimitive();
        }
        Class<?> argClass = arg.getClass();
        if (parameterType.isPrimitive()) {
            if (parameterType == boolean.class) return argClass == Boolean.class;
            if (parameterType == char.class) return argClass == Character.class;
            if (Number.class.isAssignableFrom(argClass)) {
                return parameterType == byte.class || parameterType == short.class || parameterType == int.class
                    || parameterType == long.class || parameterType == float.class || parameterType == double.class;
            }
            return false;
        }
        if (Number.class.isAssignableFrom(parameterType) && Number.class.isAssignableFrom(argClass)) {
            return true;
        }
        return parameterType.isAssignableFrom(argClass);
    }

    private Object[] coerceArguments(Class<?>[] parameterTypes, Object[] args) {
        Object[] coerced = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            coerced[i] = coerceArgument(parameterTypes[i], args[i]);
        }
        return coerced;
    }

    private Object coerceArgument(Class<?> parameterType, Object arg) {
        if (arg == null) {
            return null;
        }
        if ((parameterType.isPrimitive() || Number.class.isAssignableFrom(parameterType)) && arg instanceof Number number) {
            if (parameterType == byte.class || parameterType == Byte.class) return number.byteValue();
            if (parameterType == short.class || parameterType == Short.class) return number.shortValue();
            if (parameterType == int.class || parameterType == Integer.class) return number.intValue();
            if (parameterType == long.class || parameterType == Long.class) return number.longValue();
            if (parameterType == float.class || parameterType == Float.class) return number.floatValue();
            if (parameterType == double.class || parameterType == Double.class) return number.doubleValue();
        }
        return arg;
    }

    private Object[] toObjectArray(Object value) {
        if (value == null) {
            return new Object[0];
        }
        if (value instanceof Object[] arr) {
            return arr;
        }
        return new Object[] { value };
    }

    private String blankToNull(String value) {
        return notBlank(value) ? value : null;
    }

    private Set<Address> findDataAddresses(
        Program program,
        String datatypeQuery,
        String fieldQuery,
        MatchMode matchMode,
        boolean regexIgnoreCase
    ) {
        Set<Address> addresses = new LinkedHashSet<>();
        DataIterator iterator = program.getListing().getDefinedData(true);
        while (iterator.hasNext()) {
            Data data = iterator.next();
            if (!matchesDataType(data, datatypeQuery, matchMode, regexIgnoreCase)) {
                continue;
            }

            if (!notBlank(fieldQuery)) {
                addresses.add(data.getAddress());
                continue;
            }

            collectFieldAddresses(data, fieldQuery, matchMode, regexIgnoreCase, addresses);
        }
        return addresses;
    }

    private boolean matchesDataType(Data data, String datatypeQuery, MatchMode matchMode, boolean regexIgnoreCase) {
        if (!notBlank(datatypeQuery)) {
            return true;
        }
        DataType dataType = data.getDataType();
        String dtName = dataType != null ? dataType.getName() : "";
        String dtPath = dataType != null ? dataType.getPathName() : "";
        String dtCategory = dataType != null && dataType.getCategoryPath() != null
            ? dataType.getCategoryPath().getPath()
            : "";
        return matches(dtName, datatypeQuery, matchMode, regexIgnoreCase)
            || matches(dtPath, datatypeQuery, matchMode, regexIgnoreCase)
            || matches(dtCategory, datatypeQuery, matchMode, regexIgnoreCase);
    }

    private void collectFieldAddresses(
        Data data,
        String fieldQuery,
        MatchMode matchMode,
        boolean regexIgnoreCase,
        Set<Address> out
    ) {
        if (data == null || data.getNumComponents() <= 0) {
            return;
        }
        for (int i = 0; i < data.getNumComponents(); i++) {
            Data component = data.getComponent(i);
            if (component == null) {
                continue;
            }
            String fieldName = component.getFieldName();
            String componentPathName = component.getComponentPathName();
            if (matches(fieldName, fieldQuery, matchMode, regexIgnoreCase)
                || matches(componentPathName, fieldQuery, matchMode, regexIgnoreCase)) {
                out.add(component.getAddress());
            }
            if (component.getNumComponents() > 0) {
                collectFieldAddresses(component, fieldQuery, matchMode, regexIgnoreCase, out);
            }
        }
    }

    private List<Map<String, Object>> disassemble(Program program, Function function) {
        List<Map<String, Object>> instructions = new ArrayList<>();
        Address start = function.getEntryPoint();
        Address end = function.getBody().getMaxAddress();
        InstructionIterator iterator = program.getListing().getInstructions(start, true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            if (instruction.getAddress().compareTo(end) > 0) {
                break;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address", instruction.getAddress().toString());
            row.put("mnemonic", instruction.getMnemonicString());
            row.put("operands", instruction.toString().substring(instruction.getMnemonicString().length()).trim());

            byte[] bytes = new byte[instruction.getLength()];
            try {
                program.getMemory().getBytes(instruction.getAddress(), bytes);
                StringBuilder hex = new StringBuilder();
                for (byte b : bytes) {
                    hex.append(String.format("%02X", b & 0xFF));
                }
                row.put("bytes", hex.toString());
            } catch (Exception e) {
                row.put("bytes", "");
            }

            instructions.add(row);
        }
        return instructions;
    }

    private Map<String, Object> referenceRow(Program program, Reference ref, String direction) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("direction", direction);
        row.put("from_addr", ref.getFromAddress().toString());
        row.put("to_addr", ref.getToAddress().toString());
        row.put("ref_type", ref.getReferenceType().getName());
        row.put("is_primary", ref.isPrimary());

        Function fromFunction = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        if (fromFunction != null) {
            row.put("from_function", fromFunction.getName());
            row.put("from_function_addr", fromFunction.getEntryPoint().toString());
        }
        Function toFunction = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
        if (toFunction != null) {
            row.put("to_function", toFunction.getName());
            row.put("to_function_addr", toFunction.getEntryPoint().toString());
        }
        return row;
    }

    private boolean matchesRefType(Reference reference, String filter) {
        if (!notBlank(filter)) {
            return true;
        }
        String refName = reference.getReferenceType() != null ? reference.getReferenceType().getName() : "";
        return refName.equalsIgnoreCase(filter);
    }

    private Namespace getOrCreateNamespace(Program program, String namespacePath, boolean asClass) throws Exception {
        SymbolTable symbolTable = program.getSymbolTable();
        Namespace current = program.getGlobalNamespace();
        String normalized = normalizeNamespacePath(namespacePath);
        String[] parts = normalized.split("::");
        for (int i = 0; i < parts.length; i++) {
            String rawPart = parts[i];
            String part = rawPart.trim();
            if (part.isEmpty()) {
                continue;
            }
            boolean isLast = (i == parts.length - 1);
            Namespace next = symbolTable.getNamespace(part, current);
            if (next == null) {
                if (asClass && isLast) {
                    next = symbolTable.createClass(current, part, SourceType.USER_DEFINED);
                } else {
                    next = symbolTable.createNameSpace(current, part, SourceType.USER_DEFINED);
                }
            } else if (asClass && isLast && !(next instanceof GhidraClass)) {
                GhidraClass converted = symbolTable.convertNamespaceToClass(next);
                if (converted == null) {
                    throw new IllegalStateException("Failed to convert namespace to class: " + next.getName(true));
                }
                next = converted;
            }
            current = next;
        }
        return current;
    }

    private Function resolveFunction(Program program, Map<String, Object> args) {
        String name = str(args, "name");
        String address = str(args, "address");
        if (notBlank(name) && notBlank(address)) {
            return null;
        }
        if (notBlank(address)) {
            Address addr = parseAddress(program, address);
            if (addr == null) return null;
            Function function = program.getFunctionManager().getFunctionAt(addr);
            if (function == null) {
                function = program.getFunctionManager().getFunctionContaining(addr);
            }
            return function;
        }
        if (notBlank(name)) {
            Function exact = null;
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                if (function.getName().equals(name)) {
                    return function;
                }
                if (exact == null && function.getName().equalsIgnoreCase(name)) {
                    exact = function;
                }
            }
            return exact;
        }
        return null;
    }

    private Program requireProgram() {
        if (currentProgramSupplier != null) {
            try {
                Program supplied = currentProgramSupplier.get();
                if (supplied != null) {
                    return supplied;
                }
            } catch (Exception e) {
                Msg.debug(this, "Current program supplier failed", e);
            }
        }

        if (tool == null) {
            throw new IllegalStateException("Plugin tool is not available");
        }
        ghidra.app.services.ProgramManager programManager = tool.getService(ghidra.app.services.ProgramManager.class);
        if (programManager == null) {
            throw new IllegalStateException("ProgramManager service is unavailable");
        }
        Program program = programManager.getCurrentProgram();
        if (program != null) {
            return program;
        }

        // Application-level plugin instances may observe null current program in some tool contexts.
        // Fall back to any open program, preferring a visible one when available.
        Program[] openPrograms = programManager.getAllOpenPrograms();
        if (openPrograms != null && openPrograms.length > 0) {
            for (Program openProgram : openPrograms) {
                if (openProgram != null && programManager.isVisible(openProgram)) {
                    return openProgram;
                }
            }
            for (Program openProgram : openPrograms) {
                if (openProgram != null) {
                    return openProgram;
                }
            }
        }

        throw new IllegalStateException("No program is loaded");
    }

    private Address parseAddress(Program program, String address) {
        if (!notBlank(address)) return null;
        try {
            return program.getAddressFactory().getAddress(address);
        } catch (Exception e) {
            return null;
        }
    }

    private String normalizeNamespacePath(String namespacePath) {
        if (!notBlank(namespacePath)) {
            return "";
        }
        String normalized = namespacePath.replace('.', ':').trim();
        while (normalized.contains(":::")) {
            normalized = normalized.replace(":::", "::");
        }
        return normalized;
    }

    private String normalizeCategoryPath(String categoryPath) {
        if (!notBlank(categoryPath)) {
            return CategoryPath.ROOT.getPath();
        }

        String normalized = categoryPath.trim().replace('\\', '/');
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        while (normalized.contains("//")) {
            normalized = normalized.replace("//", "/");
        }
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String kindOf(DataType dataType) {
        if (dataType instanceof Structure) return "struct";
        if (dataType instanceof Enum) return "enum";
        if (dataType instanceof Union) return "union";
        if (dataType instanceof Array) return "array";
        if (dataType instanceof Pointer) return "pointer";
        if (dataType instanceof TypeDef) return "typedef";
        if (dataType instanceof FunctionDefinition) return "function_def";
        if (dataType instanceof BitFieldDataType) return "bitfield";
        return "other";
    }

    private String filterLines(String[] lines, Integer startLine, Integer endLine, Integer maxLines) {
        int start = startLine != null && startLine > 0 ? startLine - 1 : 0;
        int end = endLine != null && endLine > 0 ? Math.min(endLine, lines.length) : lines.length;
        if (maxLines != null && maxLines > 0) {
            end = Math.min(end, start + maxLines);
        }
        if (start >= lines.length) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = start; i < end && i < lines.length; i++) {
            if (i > start) out.append('\n');
            out.append(lines[i]);
        }
        return out.toString();
    }

    private MatchMode matchMode(Map<String, Object> args) {
        String raw = strOrDefault(args, "match_mode", "exact_ci");
        if ("regex".equalsIgnoreCase(raw)) {
            return MatchMode.REGEX;
        }
        return MatchMode.EXACT_CI;
    }

    private boolean matches(String candidate, String query, MatchMode mode, boolean regexIgnoreCase) {
        if (!notBlank(query)) {
            return true;
        }
        if (candidate == null) {
            return false;
        }
        if (mode == MatchMode.EXACT_CI) {
            return candidate.equalsIgnoreCase(query);
        }
        int flags = regexIgnoreCase ? Pattern.CASE_INSENSITIVE : 0;
        return Pattern.compile(query, flags).matcher(candidate).find();
    }

    private McpSchema.CallToolResult paginatedResult(String tool, List<Map<String, Object>> rows, int offset, int limit) {
        int start = Math.min(offset, rows.size());
        int end = Math.min(start + limit, rows.size());
        List<Map<String, Object>> page = rows.subList(start, end);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("tool", tool);
        result.put("size", rows.size());
        result.put("offset", start);
        result.put("limit", limit);
        result.put("returned", page.size());
        result.put("result", page);
        return ok(result);
    }

    private McpSchema.CallToolResult ok(Map<String, Object> payload) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(GSON.toJson(payload))
            .isError(Boolean.FALSE)
            .structuredContent(payload)
            .build();
    }

    private McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .isError(Boolean.TRUE)
            .structuredContent(Map.of("error", message))
            .build();
    }

    private Map<String, Object> safeArgs(Map<String, Object> args) {
        return args != null ? args : Collections.emptyMap();
    }

    private String str(Map<String, Object> args, String key) {
        Object val = args.get(key);
        return val != null ? String.valueOf(val) : null;
    }

    private String strOrDefault(Map<String, Object> args, String key, String defaultValue) {
        String value = str(args, key);
        return value != null ? value : defaultValue;
    }

    private boolean bool(Map<String, Object> args, String key, boolean defaultValue) {
        Object val = args.get(key);
        if (val == null) return defaultValue;
        if (val instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(val));
    }

    private Integer nullableInt(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val == null) return null;
        if (val instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(val));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Long nullableLong(Map<String, Object> args, String key) {
        Object val = args.get(key);
        if (val == null) return null;
        if (val instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(val).trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Long parseFlexibleLong(Object value) {
        return parseFlexibleLong(value, null);
    }

    private Long parseFlexibleLong(Object value, String fieldName) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }

        String raw = String.valueOf(value).trim().replace("_", "");
        if (raw.isEmpty()) {
            if (notBlank(fieldName)) {
                throw new IllegalArgumentException(fieldName + " cannot be empty");
            }
            throw new IllegalArgumentException("new_value cannot be empty");
        }

        try {
            if (raw.startsWith("-0x") || raw.startsWith("-0X")) {
                BigInteger parsed = new BigInteger(raw.substring(3), 16).negate();
                return parsed.longValueExact();
            }
            if (raw.startsWith("+0x") || raw.startsWith("+0X")) {
                raw = raw.substring(1);
            }
            if (raw.startsWith("0x") || raw.startsWith("0X")) {
                BigInteger parsed = new BigInteger(raw.substring(2), 16);
                if (parsed.bitLength() > 64) {
                    if (notBlank(fieldName)) {
                        throw new IllegalArgumentException(fieldName + " exceeds 64-bit range: " + raw);
                    }
                    throw new IllegalArgumentException("new_value exceeds 64-bit range: " + raw);
                }
                return parsed.longValue();
            }
            return Long.parseLong(raw);
        } catch (ArithmeticException | NumberFormatException e) {
            if (notBlank(fieldName)) {
                throw new IllegalArgumentException("Invalid integer value for " + fieldName + ": " + raw);
            }
            throw new IllegalArgumentException("Invalid integer value: " + raw);
        }
    }

    private String toHex(long value) {
        return "0x" + Long.toHexString(value).toUpperCase(Locale.ROOT);
    }

    private int intVal(Map<String, Object> args, String key, int defaultValue) {
        Integer parsed = nullableInt(args, key);
        return parsed != null ? parsed : defaultValue;
    }

    private int nonNegative(int value) {
        return Math.max(0, value);
    }

    private int boundedLimit(int value) {
        if (value <= 0) return DEFAULT_LIMIT;
        return Math.min(value, MAX_LIMIT);
    }

    private String callingConventionErrorMessage(Function function, String requestedCallingConvention) {
        List<String> available = availableCallingConventions(function);
        if (available.isEmpty()) {
            return "Failed to set calling convention: " + requestedCallingConvention;
        }
        return "Failed to set calling convention: " + requestedCallingConvention +
            ". Available conventions: " + String.join(", ", available);
    }

    private List<String> availableCallingConventions(Function function) {
        if (function == null || function.getProgram() == null) {
            return Collections.emptyList();
        }

        LinkedHashSet<String> conventions = new LinkedHashSet<>();
        String currentConvention = function.getCallingConventionName();
        if (notBlank(currentConvention)) {
            conventions.add(currentConvention);
        }

        try {
            PrototypeModel defaultConvention = function.getProgram().getCompilerSpec().getDefaultCallingConvention();
            if (defaultConvention != null && notBlank(defaultConvention.getName())) {
                conventions.add(defaultConvention.getName());
            }

            PrototypeModel[] callingConventions = function.getProgram().getCompilerSpec().getCallingConventions();
            if (callingConventions != null) {
                for (PrototypeModel convention : callingConventions) {
                    if (convention != null && notBlank(convention.getName())) {
                        conventions.add(convention.getName());
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to collect available calling conventions", e);
        }

        return new ArrayList<>(conventions);
    }

    private boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    private static final class Resolution<T> {
        private final T value;
        private final String error;

        private Resolution(T value, String error) {
            this.value = value;
            this.error = error;
        }

        static <T> Resolution<T> ok(T value) {
            return new Resolution<>(value, null);
        }

        static <T> Resolution<T> error(String error) {
            return new Resolution<>(null, error);
        }

        boolean isOk() {
            return error == null;
        }

        T value() {
            return value;
        }

        String error() {
            return error;
        }
    }

    private enum MatchMode {
        EXACT_CI,
        REGEX
    }
}
