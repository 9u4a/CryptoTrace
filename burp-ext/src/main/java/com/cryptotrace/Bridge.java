package com.cryptotrace;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Browser bridge: the CryptoTrace Chrome extension sends its config straight to Burp, replacing the
 * Export -> Import round trip. Listens on 127.0.0.1 only. Every request must carry the pairing token
 * (Authorization: Bearer), a Host of 127.0.0.1/localhost:port (DNS rebinding) and, when the browser sends
 * an Origin, a chrome-extension:// one (a web page can't push a config). Montoya-free for unit tests.
 *
 * <p>GET /ping -> {ok, name}. POST /config (application/json, a schemaVersion-1 config) -> the receiver's reply.
 */
public final class Bridge {
    public static final int DEFAULT_PORT = 17777;
    static final int MAX_BODY = 5 * 1024 * 1024;

    /** Applies a received config and returns the JSON reply ({ok, ...}). Throws to report a failure. */
    public interface Receiver {
        JsonObject receive(JsonObject config) throws Exception;
    }

    /** Thrown by a receiver to answer with a specific HTTP status (e.g. 403 when the user declines). */
    public static final class Refused extends Exception {
        final int status;

        public Refused(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    private final Supplier<String> token;
    private final Receiver receiver;
    private final Consumer<String> log;
    private HttpServer http;
    private int port;

    public Bridge(Supplier<String> token, Receiver receiver, Consumer<String> log) {
        this.token = token;
        this.receiver = receiver;
        this.log = log;
    }

    /** (Re)binds to 127.0.0.1:port; port 0 picks a free one (tests). */
    public synchronized void start(int port) throws IOException {
        stop();
        HttpServer s = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        s.createContext("/", this::handle);
        s.setExecutor(Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "cryptotrace-bridge");
            t.setDaemon(true);
            return t;
        }));
        s.start();
        http = s;
        this.port = s.getAddress().getPort();
    }

    public synchronized void stop() {
        if (http != null) {
            http.stop(0);
            http = null;
        }
    }

    public synchronized boolean running() {
        return http != null;
    }

    public synchronized int port() {
        return port;
    }

    private void handle(HttpExchange ex) throws IOException {
        try (ex) {
            String method = ex.getRequestMethod();
            String path = ex.getRequestURI().getPath();
            String problem = check(method, path, ex.getRequestHeaders().getFirst("Host"),
                    ex.getRequestHeaders().getFirst("Origin"), ex.getRequestHeaders().getFirst("Authorization"),
                    ex.getRequestHeaders().getFirst("Content-Type"), port(), token.get());
            if (problem != null) {
                int status = problem.startsWith("token") ? 401 : problem.startsWith("not found") ? 404 : 403;
                log.accept("bridge: rejected " + method + " " + path + " (" + problem + ")");
                reply(ex, status, error(problem));
                return;
            }
            if ("GET".equals(method)) {
                JsonObject o = new JsonObject();
                o.addProperty("ok", true);
                o.addProperty("name", "CryptoTrace");
                reply(ex, 200, o);
                return;
            }
            byte[] body = readCapped(ex.getRequestBody());
            if (body == null) {
                reply(ex, 413, error("config larger than " + MAX_BODY + " bytes"));
                return;
            }
            JsonObject cfg;
            try {
                JsonElement e = ServerClient.GSON.fromJson(new String(body, StandardCharsets.UTF_8), JsonElement.class);
                if (e == null || !e.isJsonObject()) throw new IllegalArgumentException("not a JSON object");
                cfg = e.getAsJsonObject();
            } catch (RuntimeException e) {
                reply(ex, 400, error("invalid JSON: " + e.getMessage()));
                return;
            }
            try {
                reply(ex, 200, receiver.receive(cfg));
            } catch (Refused r) {
                reply(ex, r.status, error(r.getMessage()));
            } catch (Exception e) {
                reply(ex, 500, error(String.valueOf(e.getMessage())));
            }
        }
    }

    /** Null when the request may proceed, else the reason (prefix "token" = 401, "not found" = 404, else 403). */
    static String check(String method, String path, String host, String origin, String auth, String contentType,
                        int port, String token) {
        boolean ping = "GET".equals(method) && "/ping".equals(path);
        boolean push = "POST".equals(method) && "/config".equals(path);
        if (!ping && !push) return "not found: " + method + " " + path;
        if (host == null || !(host.equalsIgnoreCase("127.0.0.1:" + port) || host.equalsIgnoreCase("localhost:" + port))) {
            return "bad Host header";
        }
        if (origin != null && !origin.isEmpty() && !origin.toLowerCase(Locale.ROOT).startsWith("chrome-extension://")) {
            return "origin not allowed: " + origin;
        }
        if (token == null || token.isEmpty() || auth == null || !auth.startsWith("Bearer ")
                || !MessageDigest.isEqual(auth.substring(7).trim().getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8))) {
            return "token missing or wrong -- copy it from Burp's CryptoTrace tab";
        }
        if (push && (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json"))) {
            return "Content-Type must be application/json";
        }
        return null;
    }

    /** True when any object in the config has a "custom" key (a JS module the server would run). */
    static boolean usesCustomCode(JsonElement e) {
        if (e == null) return false;
        if (e.isJsonArray()) {
            for (JsonElement x : e.getAsJsonArray()) if (usesCustomCode(x)) return true;
        } else if (e.isJsonObject()) {
            for (Map.Entry<String, JsonElement> m : e.getAsJsonObject().entrySet()) {
                if (m.getKey().equals("custom")) return true;
                if (usesCustomCode(m.getValue())) return true;
            }
        }
        return false;
    }

    /** File name for a received config: profile (+ first scope host), filesystem-safe. */
    /**
     * One file per target (first scope entry's host + port), not per capture: a new Send to Burp for the same
     * target replaces the previous capture. (Per-date names left old captures loaded beside the new one, and the
     * server uses the first profile whose scope matches -- the stale one.)
     */
    static String fileNameFor(JsonObject cfg) {
        String key = scopeKey(cfg);
        if (key.isEmpty()) return "received.json";
        String name = ("captured_" + key.replace(':', '_')).replaceAll("[^A-Za-z0-9._-]", "_");
        if (name.length() > 100) name = name.substring(0, 100);
        return name + ".json";
    }

    /** "host:port" (or "host") of the config's first scope entry; "" when it has none. */
    static String scopeKey(JsonObject cfg) {
        if (!cfg.has("scope") || !cfg.get("scope").isJsonArray() || cfg.getAsJsonArray("scope").isEmpty()) return "";
        JsonElement s = cfg.getAsJsonArray("scope").get(0);
        if (!s.isJsonObject()) return "";
        JsonObject o = s.getAsJsonObject();
        String host = o.has("host") && o.get("host").isJsonPrimitive() ? o.get("host").getAsString().toLowerCase() : "";
        if (host.isEmpty()) return "";
        String port = o.has("port") && o.get("port").isJsonPrimitive() ? o.get("port").getAsString() : "";
        return port.isEmpty() ? host : host + ":" + port;
    }

    private static byte[] readCapped(InputStream in) throws IOException {
        byte[] data = in.readNBytes(MAX_BODY + 1);
        return data.length > MAX_BODY ? null : data;
    }

    private static JsonObject error(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("ok", false);
        o.addProperty("error", msg);
        return o;
    }

    private static void reply(HttpExchange ex, int status, JsonObject body) throws IOException {
        byte[] b = ServerClient.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
