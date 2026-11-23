package com.cryptotrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Talks to the real Node server (requires `node` on PATH), using the sample configs. */
class ServerClientTest {
    private static final Path ROOT = Path.of(System.getProperty("cryptotrace.root", ".."));
    private ServerClient client;

    @BeforeEach
    void start() throws Exception {
        client = new ServerClient(line -> { }, 5000);
        client.start(ServerClient.command("node", ROOT.resolve("server/src/main.mjs").toString()));
        JsonObject loaded = client.load(List.of(
                ROOT.resolve("samples/configs/scenario-a.json").toString(),
                ROOT.resolve("samples/configs/scenario-c.json").toString()));
        for (var r : loaded.getAsJsonArray("results")) assertFalse(r.getAsJsonObject().has("error"), r.toString());
    }

    @AfterEach
    void stop() {
        client.close();
    }

    @Test
    void healthAndProfiles() throws Exception {
        JsonObject h = client.call("health", null);
        assertEquals(2, h.getAsJsonArray("profiles").size());
    }

    @Test
    void encryptThenDecryptRequestRoundTrip() throws Exception {
        JsonObject req = new JsonObject();
        req.addProperty("path", "/api/login");
        JsonArray headers = JsonParser.parseString("[[\"Content-Type\",\"application/json\"],[\"X-CT-Plain\",\"1\"]]").getAsJsonArray();
        req.add("headers", headers);
        req.addProperty("body", "{\"data\":{\"id\":\"<b>\",\"pw\":\"x\"}}");
        JsonObject args = new JsonObject();
        args.addProperty("host", "127.0.0.1");
        args.addProperty("port", 8088);
        args.add("request", req);

        JsonObject enc = client.call("encryptRequest", args);
        assertEquals("sample-a-login", enc.get("matched").getAsString());
        JsonObject encReq = enc.getAsJsonObject("request");
        assertEquals(1, encReq.getAsJsonArray("headers").size(), "X-CT-Plain must be stripped");
        assertTrue(JsonParser.parseString(encReq.get("body").getAsString()).getAsJsonObject().get("data").isJsonPrimitive());

        args.add("request", encReq);
        JsonObject dec = client.call("decryptRequest", args);
        JsonObject data = JsonParser.parseString(dec.getAsJsonObject("request").get("body").getAsString())
                .getAsJsonObject().getAsJsonObject("data");
        assertEquals("<b>", data.get("id").getAsString());
    }

    @Test
    void serverErrorsSurfaceAsExceptions() {
        assertThrows(ServerClient.ServerException.class, () -> client.call("nope", null));
    }

    @Test
    void notRunningIsAnError() {
        client.close();
        assertThrows(ServerClient.ServerException.class, () -> client.call("health", null));
    }

    @Test
    void restartingNeverFailsTheNewServersCalls() throws Exception {
        // The old process's reader thread used to fail EVERY pending call when it died -- including the new
        // process's first call (Burp showed "health failed: crypto server exited (code 1)" after Send to Burp).
        for (int i = 0; i < 15; i++) {
            client.start(ServerClient.command("node", ROOT.resolve("server/src/main.mjs").toString()));
            assertEquals("0.2.0", client.call("health", null).get("version").getAsString(), "restart #" + i);
        }
    }

    @Test
    void oracleQuestionsFromTheServerAreAnsweredAndTheRequestCompletes() throws Exception {
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("ct-oracle");
        java.nio.file.Path cfg = dir.resolve("o.json");
        java.nio.file.Files.writeString(cfg, "{\"schemaVersion\":1,\"profile\":\"orc\",\"scope\":[{\"host\":\"api.test\",\"pathRegex\":\".*\"}],"
                + "\"keys\":{},\"ciphers\":{\"c1\":{\"oracle\":{\"fn\":\"f@u:1:1\"}}},"
                + "\"apply\":{\"request\":[{\"in\":\"json\",\"path\":\"$.z\",\"cipher\":\"c1\"}],\"response\":[]},\"integrity\":[]}");
        // the sink stands in for the broker + browser: answer each question with "enc(<value>)"
        client.oracleSink(q -> client.oracleResult(q.get("oid").getAsInt(), true, "enc(" + q.get("value").getAsString() + ")", null));
        client.load(List.of(cfg.toString()));
        JsonObject args = JsonParser.parseString("{\"host\":\"api.test\",\"port\":443,\"request\":{\"method\":\"POST\",\"path\":\"/p\",\"headers\":[],\"body\":\"{\\\"z\\\":\\\"hi\\\"}\"}}").getAsJsonObject();
        JsonObject res = client.call("encryptRequest", args);
        assertEquals("{\"z\":\"enc(hi)\"}", res.getAsJsonObject("request").get("body").getAsString());
    }
}
