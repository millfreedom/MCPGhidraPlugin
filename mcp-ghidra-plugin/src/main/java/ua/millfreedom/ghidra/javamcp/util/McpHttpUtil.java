package ua.millfreedom.ghidra.javamcp.util;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;

public final class McpHttpUtil {

    private McpHttpUtil() {
    }

    public static void addCorsHeaders(HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Access-Control-Allow-Origin", "http://localhost");
        headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type, Accept");
        headers.set("Access-Control-Max-Age", "3600");
    }

    public static boolean handleOptionsRequest(HttpExchange exchange) throws IOException {
        if (!"OPTIONS".equalsIgnoreCase(exchange.getRequestMethod())) {
            return false;
        }
        addCorsHeaders(exchange);
        exchange.sendResponseHeaders(204, -1);
        return true;
    }
}
