package com.cryptotrace;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Browser bridge: request gate (token / Host / Origin), config routing, file naming, custom-code detection. */
class BridgeTest {
    private static final String TOKEN = "t0k3n";
    private final List<JsonObject> received = new ArrayList<>();
    private Bridge bridge;

    @AfterEach
    void stop() {
        if (bridge != null) bridge.stop();
    }

    private int start() throws Exception {
        bridge = new Bridge(() -> TOKEN, cfg -> {
            received.add(cfg);
            if (cfg.has("decline")) throw new Bridge.Refused(403, "declined in Burp");
            JsonObject o = new JsonObject();
            o.addProperty("ok", true);
            o.addProperty("status", "running");
            return o;
        }, line -> { });
        bridge.start(0);
        return bridge.port();
    }

    private static HttpResponse<String> post(int port, String auth, String origin, String body) throws Exception {
        // java.net.http sets Host itself (127.0.0.1:port); Origin is a free header there.
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/config"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        if (auth != null) b.header("Authorization", auth);
        if (origin != null) b.header("Origin", origin);
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void acceptsAPairedExtensionAndRejectsEveryoneElse() throws Exception {
        int port = start();
        HttpResponse<String> ok = post(port, "Bearer " + TOKEN, "chrome-extension://abc", "{\"profile\":\"p\"}");
        assertEquals(200, ok.statusCode());
        assertTrue(JsonParser.parseString(ok.body()).getAsJsonObject().get("ok").getAsBoolean());
        assertEquals("p", received.get(0).get("profile").getAsString());

        assertEquals(401, post(port, null, "chrome-extension://abc", "{}").statusCode());
        assertEquals(401, post(port, "Bearer wrong", null, "{}").statusCode());
        assertEquals(403, post(port, "Bearer " + TOKEN, "https://evil.example", "{}").statusCode(), "web pages can't push");
        assertEquals(400, post(port, "Bearer " + TOKEN, null, "[1,2]").statusCode());
        assertEquals(403, post(port, "Bearer " + TOKEN, null, "{\"decline\":true}").statusCode());
        assertEquals(2, received.size(), "only the valid push and the declined one reach the receiver");
    }

    @Test
    void gateChecksHostAndRoutes() {
        assertNull(Bridge.check("GET", "/ping", "127.0.0.1:17777", null, "Bearer x", null, 17777, "x"));
        assertNull(Bridge.check("POST", "/config", "localhost:17777", "chrome-extension://id", "Bearer x", "application/json", 17777, "x"));
        assertTrue(Bridge.check("POST", "/config", "evil.example:17777", null, "Bearer x", "application/json", 17777, "x")
                .contains("Host"), "DNS rebinding");
        assertTrue(Bridge.check("POST", "/config", "127.0.0.1:17777", null, "Bearer x", "text/plain", 17777, "x")
                .contains("Content-Type"));
        assertTrue(Bridge.check("GET", "/", "127.0.0.1:17777", null, "Bearer x", null, 17777, "x").startsWith("not found"));
        assertTrue(Bridge.check("GET", "/ping", "127.0.0.1:17777", null, "Bearer ", null, 17777, "").startsWith("token"),
                "an empty token never matches");
    }

    @Test
    void namesFilesSafelyAndSpotsCustomCode() {
        JsonObject cfg = JsonParser.parseString(
                "{\"profile\":\"captured-2026-11-16\",\"scope\":[{\"host\":\"*.shop.test\"}],"
                        + "\"ciphers\":{\"c1\":{\"custom\":\"custom/rabbit.js\"}}}").getAsJsonObject();
        // one file per target (host + port), not per capture date: a new capture replaces the previous one
        assertEquals("captured__.shop.test.json", Bridge.fileNameFor(cfg));
        JsonObject withPort = JsonParser.parseString("{\"profile\":\"captured-2026-11-23\",\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8088}]}").getAsJsonObject();
        assertEquals("captured_127.0.0.1_8088.json", Bridge.fileNameFor(withPort));
        assertEquals("captured_127.0.0.1_8088.json", Bridge.fileNameFor(JsonParser.parseString(
                "{\"profile\":\"captured-2026-11-19\",\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8088}]}").getAsJsonObject()));
        assertEquals("received.json", Bridge.fileNameFor(JsonParser.parseString("{\"profile\":\"../etc/passwd\"}").getAsJsonObject()));
        assertTrue(Bridge.usesCustomCode(cfg));
        assertFalse(Bridge.usesCustomCode(JsonParser.parseString("{\"ciphers\":{\"c1\":{\"alg\":\"aes-256-cbc\"}}}")));
    }

    @Test
    void scopeKeyIdentifiesTheTarget() {
        JsonObject a = JsonParser.parseString("{\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8088,\"pathRegex\":\".*\"}]}").getAsJsonObject();
        JsonObject b = JsonParser.parseString("{\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8088}],\"profile\":\"other\"}").getAsJsonObject();
        JsonObject c = JsonParser.parseString("{\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8089}]}").getAsJsonObject();
        assertEquals(Bridge.scopeKey(a), Bridge.scopeKey(b));
        assertNotEquals(Bridge.scopeKey(a), Bridge.scopeKey(c));
        assertEquals("", Bridge.scopeKey(JsonParser.parseString("{}").getAsJsonObject()));
    }

    @Test
    void oracleJobsGoToThePollingPanelAndResultsComeBack() throws Exception {
        List<String> replies = new ArrayList<>();
        OracleBroker broker = new OracleBroker((oid, ok, value, error) -> replies.add(oid + ":" + ok + ":" + (ok ? value : error)));
        broker.enabled(true);
        broker.minIntervalMs(0);
        bridge = new Bridge(() -> TOKEN, cfg -> new JsonObject(), line -> { }, broker);
        bridge.start(0);
        int port = bridge.port();
        HttpClient http = HttpClient.newHttpClient();
        java.util.function.Function<String, HttpRequest.Builder> req = (path) -> HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Authorization", "Bearer " + TOKEN).header("Origin", "chrome-extension://abc");
        // the panel long-polls; a job submitted meanwhile is handed to it
        java.util.concurrent.CompletableFuture<HttpResponse<String>> poll = http.sendAsync(req.apply("/oracle/next?wait=3000").GET().build(), HttpResponse.BodyHandlers.ofString());
        Thread.sleep(300);
        // the long poll must not block config pushes (multi-threaded bridge)
        assertEquals(200, post(port, "Bearer " + TOKEN, "chrome-extension://abc", "{\"profile\":\"p\"}").statusCode());
        broker.submit(JsonParser.parseString("{\"oid\":9,\"fn\":\"f@u:1:1\",\"dir\":\"encrypt\",\"value\":\"hello\"}").getAsJsonObject());
        JsonObject job = JsonParser.parseString(poll.get(5, java.util.concurrent.TimeUnit.SECONDS).body()).getAsJsonObject().getAsJsonObject("job");
        assertEquals(9, job.get("oid").getAsInt());
        HttpResponse<String> done = http.send(req.apply("/oracle/result").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"oid\":9,\"ok\":true,\"value\":\"c2Vj\"}")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, done.statusCode());
        assertEquals(List.of("9:true:c2Vj"), replies);
        // a web page (wrong origin) can't poll jobs
        assertEquals(403, http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/oracle/next")).header("Authorization", "Bearer " + TOKEN)
                .header("Origin", "https://evil.test").GET().build(), HttpResponse.BodyHandlers.ofString()).statusCode());
    }
}
