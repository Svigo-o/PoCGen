// Burp Suite extension exposing an HTTP API for listing, exporting and replaying captured requests.
// Compatible with JDK 21 and Gradle 8.11+.

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

import fi.iki.elonen.NanoHTTPD;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class BurpExtender implements IBurpExtender, IHttpListener, IExtensionStateListener {
    private static final String API_HOST = System.getProperty(
            "burp.api.host",
            System.getenv().getOrDefault("BURP_API_HOST", "127.0.0.1")
    );
    private static final int API_PORT = Integer.parseInt(System.getProperty(
            "burp.api.port",
            System.getenv().getOrDefault("BURP_API_PORT", "7001")
    ));
    private static final int MAX_CAPTURED = Integer.parseInt(System.getProperty(
            "burp.api.maxCaptured",
            System.getenv().getOrDefault("BURP_API_MAX_CAPTURED", "500")
    ));

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpApiServer httpServer;

    private final Object captureLock = new Object();
    private final LinkedHashMap<Integer, IHttpRequestResponse> captured = new LinkedHashMap<>();
    private int nextId = 0;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("LLM Proxy Controller");
        callbacks.registerHttpListener(this);
        callbacks.registerExtensionStateListener(this);
        startHttpApi();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            return;
        }
        synchronized (captureLock) {
            captured.put(nextId++, messageInfo);
            while (captured.size() > MAX_CAPTURED) {
                Iterator<Integer> iterator = captured.keySet().iterator();
                if (iterator.hasNext()) {
                    iterator.next();
                    iterator.remove();
                } else {
                    break;
                }
            }
        }
    }

    private void startHttpApi() {
        try {
            httpServer = new BurpApiServer(API_HOST, API_PORT);
            httpServer.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
            callbacks.printOutput("HTTP API listening on http://" + API_HOST + ":" + API_PORT);
        } catch (IOException e) {
            callbacks.printError("Failed to start HTTP API: " + e.getMessage());
        }
    }

    private void stopHttpApi() {
        if (httpServer != null) {
            httpServer.stop();
            httpServer = null;
        }
    }

    private IHttpRequestResponse getById(String idParam) {
        try {
            int id = Integer.parseInt(idParam);
            synchronized (captureLock) {
                return captured.get(id);
            }
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> result = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return result;
        }
        for (String pair : rawQuery.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                result.put(urlDecode(kv[0]), urlDecode(kv[1]));
            } else if (kv.length == 1) {
                result.put(urlDecode(kv[0]), "");
            }
        }
        return result;
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String errorJson(String message) {
        return "{\"error\":\"" + escape(message) + "\"}";
    }

    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void extensionUnloaded() {
        stopHttpApi();
        if (callbacks != null) {
            callbacks.printOutput("HTTP API stopped");
        }
    }

    private class BurpApiServer extends NanoHTTPD {
        BurpApiServer(String hostname, int port) throws IOException {
            super(hostname, port);
        }

        @Override
        public NanoHTTPD.Response serve(IHTTPSession session) {
            String uri = session.getUri();
            try {
                return switch (uri) {
                    case "/health" -> jsonResponse(NanoHTTPD.Response.Status.OK, "{\"status\":\"ok\"}");
                    case "/list" -> handleList();
                    case "/get_raw" -> handleGetRaw(session);
                    case "/replay_raw" -> handleReplayRaw(session);
                    default -> jsonResponse(NanoHTTPD.Response.Status.NOT_FOUND, errorJson("unknown path"));
                };
            } catch (Exception e) {
                return jsonResponse(NanoHTTPD.Response.Status.INTERNAL_ERROR, errorJson(e.getMessage()));
            }
        }

        private NanoHTTPD.Response handleList() {
            List<String> items = new ArrayList<>();
            synchronized (captureLock) {
                for (Map.Entry<Integer, IHttpRequestResponse> entry : captured.entrySet()) {
                    IHttpRequestResponse rr = entry.getValue();
                    IRequestInfo info = helpers.analyzeRequest(rr);
                    IHttpService service = rr.getHttpService();
                    String json = "{" +
                            "\"id\":" + entry.getKey() + "," +
                            "\"method\":\"" + escape(info.getMethod()) + "\"," +
                            "\"url\":\"" + escape(String.valueOf(info.getUrl())) + "\"," +
                            "\"host\":\"" + escape(service.getHost()) + "\"," +
                            "\"port\":" + service.getPort() + "," +
                            "\"https\":" + service.getProtocol().equalsIgnoreCase("https") +
                            "}";
                    items.add(json);
                }
            }
            return jsonResponse(NanoHTTPD.Response.Status.OK, "[" + String.join(",", items) + "]");
        }

        private NanoHTTPD.Response handleGetRaw(IHTTPSession session) {
            Map<String, String> query = parseQuery(session.getQueryParameterString());
            String idParam = query.get("id");
            if (idParam == null) {
                return jsonResponse(NanoHTTPD.Response.Status.BAD_REQUEST, errorJson("missing id"));
            }
            IHttpRequestResponse rr = getById(idParam);
            if (rr == null) {
                return jsonResponse(NanoHTTPD.Response.Status.NOT_FOUND, errorJson("not found"));
            }
            byte[] payload = rr.getRequest();
            return octetResponse(NanoHTTPD.Response.Status.OK, payload);
        }

        private NanoHTTPD.Response handleReplayRaw(IHTTPSession session) throws IOException {
            Map<String, String> query = parseQuery(session.getQueryParameterString());
            String host = query.get("host");
            String portParam = query.getOrDefault("port", "80");
            String httpsParam = query.getOrDefault("https", "false");

            if (host == null || host.isBlank()) {
                return jsonResponse(NanoHTTPD.Response.Status.BAD_REQUEST, errorJson("host is required"));
            }

            int port;
            try {
                port = Integer.parseInt(portParam);
            } catch (NumberFormatException e) {
                return jsonResponse(NanoHTTPD.Response.Status.BAD_REQUEST, errorJson("invalid port"));
            }

            boolean https = Boolean.parseBoolean(httpsParam);
            byte[] raw = readBody(session);

            try {
                IHttpService service = helpers.buildHttpService(host, port, https ? "https" : "http");
                IHttpRequestResponse replayResult = callbacks.makeHttpRequest(service, raw);
                byte[] response = replayResult != null && replayResult.getResponse() != null
                        ? replayResult.getResponse()
                        : new byte[0];
                return octetResponse(NanoHTTPD.Response.Status.OK, response);
            } catch (Exception e) {
                return jsonResponse(NanoHTTPD.Response.Status.INTERNAL_ERROR, errorJson("replay failed: " + e.getMessage()));
            }
        }

        private byte[] readBody(IHTTPSession session) throws IOException {
            var headers = session.getHeaders();
            long length = 0;
            if (headers != null && headers.containsKey("content-length")) {
                length = Long.parseLong(headers.get("content-length"));
            }
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            long remaining = length > 0 ? length : Long.MAX_VALUE;
            while (remaining > 0) {
                int read = session.getInputStream().read(chunk, 0, (int) Math.min(chunk.length, remaining));
                if (read == -1) {
                    break;
                }
                buffer.write(chunk, 0, read);
                if (length > 0) {
                    remaining -= read;
                }
            }
            return buffer.toByteArray();
        }

        private NanoHTTPD.Response jsonResponse(NanoHTTPD.Response.Status status, String body) {
            return NanoHTTPD.newFixedLengthResponse(status, "application/json; charset=utf-8", body);
        }

        private NanoHTTPD.Response octetResponse(NanoHTTPD.Response.Status status, byte[] body) {
            return NanoHTTPD.newFixedLengthResponse(status, "application/octet-stream", new ByteArrayInputStream(body), body.length);
        }
    }
}
