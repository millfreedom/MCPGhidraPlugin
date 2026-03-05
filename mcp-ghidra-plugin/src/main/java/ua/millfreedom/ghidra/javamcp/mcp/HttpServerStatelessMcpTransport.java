package ua.millfreedom.ghidra.javamcp.mcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import ua.millfreedom.ghidra.javamcp.util.McpHttpUtil;
import ghidra.util.Msg;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpStatelessServerHandler;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpStatelessServerTransport;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stateless MCP transport provider for com.sun.net.httpserver.HttpServer.
 *
 * This enables a native Java MCP endpoint ("/mcp") directly inside the Ghidra plugin
 * without requiring servlet containers or external bridge processes.
 */
public class HttpServerStatelessMcpTransport implements McpStatelessServerTransport, HttpHandler {

    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(60);

    private final ObjectMapper objectMapper;
    private final Duration requestTimeout;

    private volatile McpStatelessServerHandler mcpHandler;

    public HttpServerStatelessMcpTransport() {
        this(new ObjectMapper(), DEFAULT_REQUEST_TIMEOUT);
    }

    public HttpServerStatelessMcpTransport(ObjectMapper objectMapper, Duration requestTimeout) {
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();
        this.requestTimeout = requestTimeout != null ? requestTimeout : DEFAULT_REQUEST_TIMEOUT;
    }

    @Override
    public void setMcpHandler(McpStatelessServerHandler mcpHandler) {
        this.mcpHandler = mcpHandler;
    }

    @Override
    public Mono<Void> closeGracefully() {
        return Mono.empty();
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        try {
            if (McpHttpUtil.handleOptionsRequest(exchange)) {
                return;
            }
            McpHttpUtil.addCorsHeaders(exchange);

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendError(exchange, 405, "Only POST is supported on /mcp");
                return;
            }

            if (mcpHandler == null) {
                sendError(exchange, 503, "MCP server is not ready");
                return;
            }

            JsonNode root;
            try {
                root = objectMapper.readTree(exchange.getRequestBody());
            } catch (Exception e) {
                Msg.error(this, "Failed to parse MCP request JSON", e);
                sendJson(exchange, 200, createErrorResponse(null, McpSchema.ErrorCodes.PARSE_ERROR,
                    "Parse error: invalid JSON payload", e.getMessage()));
                return;
            }

            if (root == null || root.isNull()) {
                sendJson(exchange, 200, createErrorResponse(null, McpSchema.ErrorCodes.INVALID_REQUEST,
                    "Invalid request: empty JSON payload", null));
                return;
            }

            if (root.isArray()) {
                handleBatch(exchange, root);
                return;
            }

            handleSingle(exchange, root);
        } catch (Exception e) {
            Msg.error(this, "Unhandled MCP transport error", e);
            sendError(exchange, 500, "Internal MCP transport error: " + e.getMessage());
        }
    }

    private void handleSingle(HttpExchange exchange, JsonNode node) throws IOException {
        if (!node.isObject()) {
            sendJson(exchange, 200, createErrorResponse(null, McpSchema.ErrorCodes.INVALID_REQUEST,
                "Invalid request: expected JSON object", null));
            return;
        }

        McpSchema.JSONRPCResponse response = processMessage(node, exchange);
        if (response == null) {
            // Notification: no response body
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }

        sendJson(exchange, 200, response);
    }

    private void handleBatch(HttpExchange exchange, JsonNode rootArray) throws IOException {
        if (rootArray.isEmpty()) {
            sendJson(exchange, 200, createErrorResponse(null, McpSchema.ErrorCodes.INVALID_REQUEST,
                "Invalid request: empty batch", null));
            return;
        }

        List<McpSchema.JSONRPCResponse> responses = new ArrayList<>();
        for (JsonNode item : rootArray) {
            McpSchema.JSONRPCResponse response = processMessage(item, exchange);
            if (response != null) {
                responses.add(response);
            }
        }

        if (responses.isEmpty()) {
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
            return;
        }

        sendJson(exchange, 200, responses);
    }

    private McpSchema.JSONRPCResponse processMessage(JsonNode node, HttpExchange exchange) {
        if (!node.isObject()) {
            return createErrorResponse(null, McpSchema.ErrorCodes.INVALID_REQUEST,
                "Invalid request: batch item is not an object", null);
        }

        JsonNode methodNode = node.get("method");
        if (methodNode == null || !methodNode.isTextual()) {
            return createErrorResponse(node.path("id").isMissingNode() ? null : asRawId(node.get("id")),
                McpSchema.ErrorCodes.INVALID_REQUEST,
                "Invalid request: missing method", null);
        }

        Object requestId = node.has("id") ? asRawId(node.get("id")) : null;
        Map<String, Object> contextMap = new LinkedHashMap<>();
        contextMap.put("remoteAddress", exchange.getRemoteAddress() != null ? exchange.getRemoteAddress().toString() : "");
        contextMap.put("path", exchange.getRequestURI() != null ? exchange.getRequestURI().getPath() : "");
        contextMap.put("method", exchange.getRequestMethod());
        McpTransportContext context = McpTransportContext.create(contextMap);

        try {
            if (requestId == null) {
                McpSchema.JSONRPCNotification notification =
                    objectMapper.convertValue(node, McpSchema.JSONRPCNotification.class);
                mcpHandler.handleNotification(context, notification).block(requestTimeout);
                return null;
            }

            McpSchema.JSONRPCRequest request =
                objectMapper.convertValue(node, McpSchema.JSONRPCRequest.class);

            McpSchema.JSONRPCResponse response =
                mcpHandler.handleRequest(context, request).block(requestTimeout);
            if (response == null) {
                return createErrorResponse(requestId, McpSchema.ErrorCodes.INTERNAL_ERROR,
                    "Internal error: handler produced no response", null);
            }
            return response;
        } catch (Exception e) {
            Msg.error(this, "MCP request handling failed for method: " + methodNode.asText(), e);
            return createErrorResponse(requestId, McpSchema.ErrorCodes.INTERNAL_ERROR,
                "Internal error while handling MCP request", e.getMessage());
        }
    }

    private Object asRawId(JsonNode idNode) {
        if (idNode == null || idNode.isNull()) {
            return null;
        }
        if (idNode.isIntegralNumber()) {
            return idNode.longValue();
        }
        if (idNode.isFloatingPointNumber()) {
            return idNode.doubleValue();
        }
        if (idNode.isTextual()) {
            return idNode.textValue();
        }
        return idNode.toString();
    }

    private McpSchema.JSONRPCResponse createErrorResponse(Object id, int code, String message, Object data) {
        McpSchema.JSONRPCResponse.JSONRPCError error =
            new McpSchema.JSONRPCResponse.JSONRPCError(code, message, data);
        return new McpSchema.JSONRPCResponse("2.0", id, null, error);
    }

    private void sendError(HttpExchange exchange, int status, String message) throws IOException {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        McpHttpUtil.addCorsHeaders(exchange);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private void sendJson(HttpExchange exchange, int status, Object body) throws IOException {
        byte[] bytes = objectMapper.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        McpHttpUtil.addCorsHeaders(exchange);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
