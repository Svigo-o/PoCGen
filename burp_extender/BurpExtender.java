// Minimal Burp extension exposing HTTP API for list/get_raw/replay_raw
// Build: compile with burp-extender-api.jar on classpath, then load JAR in Burp Extender

import burp.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final List<IHttpRequestResponse> captured = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("LLM Proxy Controller");
        callbacks.registerHttpListener(this);
        startHttpApi();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest) {
            captured.add(messageInfo);
        }
    }

    private void startHttpApi() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 7001), 0);
            server.createContext("/list", this::handleList);
            server.createContext("/get_raw", this::handleGetRaw);
            server.createContext("/replay_raw", this::handleReplayRaw);
            server.setExecutor(null);
            server.start();
            callbacks.printOutput("HTTP API listening on http://127.0.0.1:7001");
        } catch (IOException e) {
            callbacks.printError("Failed to start HTTP API: " + e.getMessage());
        }
    }

    private void handleList(HttpExchange ex) throws IOException {
        List<Map<String, Object>> items = new ArrayList<>();
        synchronized (captured) {
            for (int i = 0; i < captured.size(); i++) {
                IHttpRequestResponse rr = captured.get(i);
                IRequestInfo ri = helpers.analyzeRequest(rr);
                Map<String, Object> m = new HashMap<>();
                m.put("id", i);
                m.put("method", ri.getMethod());
                m.put("url", ri.getUrl().toString());
                m.put("host", rr.getHttpService().getHost());
                m.put("port", rr.getHttpService().getPort());
                m.put("https", rr.getHttpService().getProtocol().equalsIgnoreCase("https"));
                items.add(m);
            }
        }
        byte[] body = toJson(items).getBytes(StandardCharsets.UTF_8);
        respondJson(ex, 200, body);
    }

    private void handleGetRaw(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getQuery());
        int id = Integer.parseInt(q.getOrDefault("id", "-1"));
        IHttpRequestResponse rr = getById(id);
        if (rr == null) {
            respondJson(ex, 404, "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8));
            return;
        }
        byte[] raw = rr.getRequest();
        respondOctet(ex, 200, raw);
    }

    private void handleReplayRaw(HttpExchange ex) throws IOException {
        Map<String, String> q = parseQuery(ex.getRequestURI().getQuery());
        String host = q.get("host");
        int port = Integer.parseInt(q.getOrDefault("port", "80"));
        boolean https = Boolean.parseBoolean(q.getOrDefault("https", "false"));
        byte[] raw = ex.getRequestBody().readAllBytes();

        IHttpService svc = helpers.buildHttpService(host, port, https ? "https" : "http");
        byte[] resp = callbacks.makeHttpRequest(svc, raw);
        respondOctet(ex, 200, resp);
    }

    private IHttpRequestResponse getById(int id) {
        synchronized (captured) {
            if (id >= 0 && id < captured.size()) return captured.get(id);
            return null;
        }
    }

    private void respondJson(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, body.length);
        ex.getResponseBody().write(body);
        ex.close();
    }

    private void respondOctet(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "application/octet-stream");
        ex.sendResponseHeaders(status, body.length);
        ex.getResponseBody().write(body);
        ex.close();
    }

    private String toJson(List<Map<String, Object>> items) {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        for (int i = 0; i < items.size(); i++) {
            Map<String, Object> m = items.get(i);
            sb.append("{");
            int c = 0;
            for (Map.Entry<String, Object> e : m.entrySet()) {
                if (c++ > 0) sb.append(",");
                sb.append("\"").append(e.getKey()).append("\":\"").append(String.valueOf(e.getValue())).append("\"");
            }
            sb.append("}");
            if (i < items.size() - 1) sb.append(",");
        }
        sb.append("]");
        return sb.toString();
    }

    private Map<String, String> parseQuery(String q) {
        Map<String, String> m = new HashMap<>();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            String[] parts = kv.split("=", 2);
            if (parts.length == 2) m.put(parts[0], parts[1]);
        }
        return m;
    }
}
