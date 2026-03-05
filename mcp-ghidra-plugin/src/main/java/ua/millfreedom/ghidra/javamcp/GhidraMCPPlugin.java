package ua.millfreedom.ghidra.javamcp;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpServer;
import ua.millfreedom.ghidra.javamcp.mcp.NativeMcpServer;
import ua.millfreedom.ghidra.javamcp.util.McpHttpUtil;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra MCP",
    description = "Native Java-only MCP endpoint for Ghidra.",
    servicesRequired = { ProgramManager.class }
)
public class GhidraMCPPlugin extends ProgramPlugin {

    private static final int DEFAULT_PORT = 8192;
    private static final int MAX_PORT_ATTEMPTS = 256;
    private static final String PLUGIN_VERSION = "1.0.0";
    private static final Gson GSON = new Gson();

    private static final Map<Integer, GhidraMCPPlugin> ACTIVE = new ConcurrentHashMap<>();

    private HttpServer server;
    private NativeMcpServer nativeMcpServer;
    private int port;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        this.port = findAvailablePort();
        ACTIVE.put(this.port, this);
        try {
            startServer();
            Msg.info(this, "Ghidra MCP server started on port " + port);
        } catch (IOException e) {
            Msg.error(this, "Failed to start Java-only MCP server", e);
        }
    }

    private void startServer() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newCachedThreadPool());

        this.nativeMcpServer = new NativeMcpServer(tool, port, PLUGIN_VERSION, this::getCurrentProgram);
        this.nativeMcpServer.register(server);

        registerRootEndpoint(server);

        new Thread(() -> {
            server.start();
            System.out.println("[MCPGhidraPlugin] server started on port " + port);
        }, "MCPGhidraPlugin-HTTP").start();
    }

    private void registerRootEndpoint(HttpServer server) {
        server.createContext("/", exchange -> {
            try {
                if (McpHttpUtil.handleOptionsRequest(exchange)) {
                    return;
                }

                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    byte[] body = "Method Not Allowed".getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
                    McpHttpUtil.addCorsHeaders(exchange);
                    exchange.sendResponseHeaders(405, body.length);
                    exchange.getResponseBody().write(body);
                    exchange.close();
                    return;
                }

                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("name", "MCPGhidraPlugin");
                payload.put("version", PLUGIN_VERSION);
                payload.put("port", port);
                payload.put("mcp_endpoint", "/mcp");

                byte[] bytes = GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
                McpHttpUtil.addCorsHeaders(exchange);
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            } catch (Exception e) {
                Msg.error(this, "Root handler error", e);
                try {
                    exchange.sendResponseHeaders(500, -1);
                } catch (IOException ignored) {
                    // no-op
                }
            }
        });
    }

    private int findAvailablePort() {
        String configuredPort = System.getProperty("ghidra.mcp.port");
        if (configuredPort != null && !configuredPort.isBlank()) {
            try {
                int candidate = Integer.parseInt(configuredPort.trim());
                if (isPortAvailable(candidate) && !ACTIVE.containsKey(candidate)) {
                    return candidate;
                }
            } catch (NumberFormatException ignored) {
                // fall through to default scan
            }
        }

        for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
            int candidate = DEFAULT_PORT + i;
            if (!ACTIVE.containsKey(candidate) && isPortAvailable(candidate)) {
                return candidate;
            }
        }

        throw new IllegalStateException("No available port found in range " + DEFAULT_PORT + "-" + (DEFAULT_PORT + MAX_PORT_ATTEMPTS - 1));
    }

    private boolean isPortAvailable(int candidate) {
        try (ServerSocket s = new ServerSocket(candidate)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    @Override
    public void dispose() {
        if (nativeMcpServer != null) {
            nativeMcpServer.close();
            nativeMcpServer = null;
        }
        if (server != null) {
            server.stop(0);
            server = null;
        }
        ACTIVE.remove(port);
        super.dispose();
    }
}
