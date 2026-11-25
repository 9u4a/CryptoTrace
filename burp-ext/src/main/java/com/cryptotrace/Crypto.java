package com.cryptotrace;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Montoya <-> server protocol. Rebuilds messages by diffing headers so HTTP/2 metadata is preserved. */
public final class Crypto {
    public static final String PLAIN_MARKER = "X-CT-Plain";

    private final ServerClient server;
    private final Scopes scopes;
    /** Editor tabs call from Burp's UI thread: they wait at most this long, never the 12 s pipeline timeout. */
    static final long UI_TIMEOUT_MS = 3000;
    private static final int CACHE_SIZE = 256;
    /** Successful decrypts for the editor tabs, so clicking through Proxy history doesn't re-ask the server. */
    private final Map<String, Result<?>> cache = java.util.Collections.synchronizedMap(
            new java.util.LinkedHashMap<>(64, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Result<?>> e) {
                    return size() > CACHE_SIZE;
                }
            });

    public Crypto(ServerClient server) {
        this(server, new Scopes());
    }

    public Crypto(ServerClient server, Scopes scopes) {
        this.server = server;
        this.scopes = scopes;
    }

    /** Whether any loaded profile covers this request -- local check, no server call. */
    public boolean inScope(HttpRequest req) {
        return req != null && req.httpService() != null
                && scopes.matches(req.httpService().host(), req.httpService().port(), req.path());
    }

    /** decryptRequest for the editor tab: cached, short timeout. */
    @SuppressWarnings("unchecked")
    public Result<HttpRequest> decryptRequestForUi(HttpRequest req) throws ServerClient.ServerException {
        String key = cacheKey("rq", req, null);
        Result<?> hit = cache.get(key);
        if (hit != null) return (Result<HttpRequest>) hit;
        Result<HttpRequest> r = requestOp("decryptRequest", req, false, UI_TIMEOUT_MS);
        if (r.matched() != null && r.allOk()) cache.put(key, r); // errors (e.g. key not captured yet) may clear up
        return r;
    }

    /** decryptResponse for the editor tab: cached, short timeout. */
    @SuppressWarnings("unchecked")
    public Result<HttpResponse> decryptResponseForUi(HttpRequest req, HttpResponse res) throws ServerClient.ServerException {
        String key = cacheKey("rs", req, res);
        Result<?> hit = cache.get(key);
        if (hit != null) return (Result<HttpResponse>) hit;
        Result<HttpResponse> r = responseOp("decryptResponse", req, res, UI_TIMEOUT_MS);
        if (r.matched() != null && r.allOk()) cache.put(key, r);
        return r;
    }

    private String cacheKey(String kind, HttpRequest req, HttpResponse res) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update((kind + "|" + scopes.generation() + "|" + req.httpService().host() + "|" + req.httpService().port() + "|")
                    .getBytes(StandardCharsets.UTF_8));
            md.update(req.toByteArray().getBytes());
            if (res != null) {
                md.update((byte) 0);
                md.update(res.toByteArray().getBytes());
            }
            return java.util.HexFormat.of().formatHex(md.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Result of a transform. `matched` is the profile name or null when out of scope. */
    public record Result<T>(String matched, T message, JsonArray applied) {
        public boolean allOk() {
            for (JsonElement a : applied) if (!isOk(a.getAsJsonObject())) return false;
            return true;
        }

        public String errors() {
            StringBuilder sb = new StringBuilder();
            for (JsonElement a : applied) {
                JsonObject o = a.getAsJsonObject();
                if (!isOk(o)) {
                    sb.append(str(o, "in", "?")).append(' ').append(str(o, "where", "?"))
                            .append(": ").append(str(o, "error", "unknown error")).append("; ");
                }
            }
            return sb.length() == 0 ? "unknown error" : sb.toString();
        }

        /** A missing or null "ok" counts as a failure. */
        static boolean isOk(JsonObject o) {
            JsonElement ok = o.get("ok");
            return ok != null && !ok.isJsonNull() && ok.getAsBoolean();
        }

        private static String str(JsonObject o, String key, String fallback) {
            JsonElement v = o.get(key);
            return v == null || v.isJsonNull() ? fallback : v.getAsString();
        }
    }

    public Result<HttpRequest> decryptRequest(HttpRequest req) throws ServerClient.ServerException {
        return requestOp("decryptRequest", req);
    }

    /** Encrypts every configured location and strips the X-CT-Plain marker. */
    public Result<HttpRequest> encryptRequest(HttpRequest req) throws ServerClient.ServerException {
        return requestOp("encryptRequest", req, false);
    }

    /** encryptRequest that never waits for the browser oracle (oracle ciphers fail at once): for the UI thread. */
    public Result<HttpRequest> encryptRequestNow(HttpRequest req) throws ServerClient.ServerException {
        return requestOp("encryptRequest", req, true);
    }

    public Result<HttpResponse> decryptResponse(HttpRequest req, HttpResponse res) throws ServerClient.ServerException {
        return responseOp("decryptResponse", req, res);
    }

    public Result<HttpResponse> encryptResponse(HttpRequest req, HttpResponse res) throws ServerClient.ServerException {
        return responseOp("encryptResponse", req, res);
    }

    private Result<HttpRequest> requestOp(String op, HttpRequest req) throws ServerClient.ServerException {
        return requestOp(op, req, false);
    }

    private Result<HttpRequest> requestOp(String op, HttpRequest req, boolean noOracle) throws ServerClient.ServerException {
        return requestOp(op, req, noOracle, -1);
    }

    private Result<HttpRequest> requestOp(String op, HttpRequest req, boolean noOracle, long timeoutMs) throws ServerClient.ServerException {
        JsonObject msg = new JsonObject();
        msg.addProperty("path", req.path());
        msg.add("headers", headersJson(req.headers()));
        putBody(msg, req.body());
        JsonObject args = target(req);
        args.add("request", msg);
        if (noOracle) args.addProperty("noOracle", true);
        JsonObject res = timeoutMs > 0 ? server.call(op, args, timeoutMs) : server.call(op, args);
        String matched = res.get("matched").isJsonNull() ? null : res.get("matched").getAsString();
        JsonObject out = res.getAsJsonObject("request");
        HttpRequest rebuilt = req;
        if (out.has("path") && !out.get("path").getAsString().equals(req.path())) rebuilt = rebuilt.withPath(out.get("path").getAsString());
        rebuilt = applyHeaders(rebuilt, req.headers(), out.getAsJsonArray("headers"));
        rebuilt = isBase64Body(out) ? rebuilt.withBody(decodeBody(out)) : rebuilt.withBody(ByteArray.byteArray(Utf8.bytes(out.get("body").getAsString())));
        return new Result<>(matched, rebuilt, res.getAsJsonArray("applied"));
    }

    /** Send the body as text when it is valid UTF-8, else base64 with bodyEncoding so bytes survive. */
    private static void putBody(JsonObject msg, ByteArray body) {
        byte[] raw = body.getBytes();
        if (isUtf8(raw)) {
            msg.addProperty("body", Utf8.text(raw));
        } else {
            msg.addProperty("body", Base64.getEncoder().encodeToString(raw));
            msg.addProperty("bodyEncoding", "base64");
        }
    }

    private static boolean isBase64Body(JsonObject out) {
        return out.has("bodyEncoding") && !out.get("bodyEncoding").isJsonNull() && "base64".equals(out.get("bodyEncoding").getAsString());
    }

    private static ByteArray decodeBody(JsonObject out) {
        return ByteArray.byteArray(Base64.getDecoder().decode(out.get("body").getAsString()));
    }

    private static boolean isUtf8(byte[] b) {
        try {
            StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(b));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    private Result<HttpResponse> responseOp(String op, HttpRequest req, HttpResponse resp) throws ServerClient.ServerException {
        return responseOp(op, req, resp, -1);
    }

    private Result<HttpResponse> responseOp(String op, HttpRequest req, HttpResponse resp, long timeoutMs) throws ServerClient.ServerException {
        JsonObject msg = new JsonObject();
        msg.add("headers", headersJson(resp.headers()));
        putBody(msg, resp.body());
        JsonObject args = target(req);
        args.addProperty("path", req.path());
        args.add("response", msg);
        JsonObject res = timeoutMs > 0 ? server.call(op, args, timeoutMs) : server.call(op, args);
        String matched = res.get("matched").isJsonNull() ? null : res.get("matched").getAsString();
        JsonObject out = res.getAsJsonObject("response");
        HttpResponse rebuilt = resp;
        JsonArray headers = out.getAsJsonArray("headers");
        Map<String, String> want = toMap(headers);
        for (HttpHeader h : resp.headers()) if (!want.containsKey(h.name().toLowerCase())) rebuilt = rebuilt.withRemovedHeader(h.name());
        for (JsonElement e : headers) {
            String n = e.getAsJsonArray().get(0).getAsString();
            String v = Utf8.toBurpHeader(e.getAsJsonArray().get(1).getAsString());
            rebuilt = rebuilt.hasHeader(n) ? rebuilt.withUpdatedHeader(n, v) : rebuilt.withAddedHeader(n, v);
        }
        rebuilt = isBase64Body(out) ? rebuilt.withBody(decodeBody(out)) : rebuilt.withBody(ByteArray.byteArray(Utf8.bytes(out.get("body").getAsString())));
        return new Result<>(matched, rebuilt, res.getAsJsonArray("applied"));
    }

    private static HttpRequest applyHeaders(HttpRequest req, List<HttpHeader> before, JsonArray after) {
        Map<String, String> want = toMap(after);
        HttpRequest r = req;
        for (HttpHeader h : before) if (!want.containsKey(h.name().toLowerCase())) r = r.withRemovedHeader(h.name());
        for (JsonElement e : after) {
            String n = e.getAsJsonArray().get(0).getAsString();
            String v = Utf8.toBurpHeader(e.getAsJsonArray().get(1).getAsString());
            String old = r.headerValue(n);
            if (old == null) r = r.withAddedHeader(n, v);
            else if (!old.equals(v)) r = r.withUpdatedHeader(n, v);
        }
        return r;
    }

    private static Map<String, String> toMap(JsonArray headers) {
        Map<String, String> m = new HashMap<>();
        for (JsonElement e : headers) m.put(e.getAsJsonArray().get(0).getAsString().toLowerCase(), e.getAsJsonArray().get(1).getAsString());
        return m;
    }

    private static JsonArray headersJson(List<HttpHeader> headers) {
        JsonArray arr = new JsonArray();
        for (HttpHeader h : headers) {
            JsonArray pair = new JsonArray();
            pair.add(h.name());
            pair.add(Utf8.fromBurpHeader(h.value())); // real text for the server
            arr.add(pair);
        }
        return arr;
    }

    private static JsonObject target(HttpRequest req) {
        JsonObject args = new JsonObject();
        args.addProperty("host", req.httpService().host());
        args.addProperty("port", req.httpService().port());
        return args;
    }

    /** A non-empty reason for a blocked request, even when the exception has no message. */
    public static String reason(Throwable e) {
        String m = e.getMessage();
        return m == null || m.isBlank() ? e.getClass().getSimpleName() : m;
    }

    /** Applied entries as simple (in, where) pairs, for insertion-point discovery. */
    public static List<String[]> appliedLocations(JsonArray applied) {
        List<String[]> out = new ArrayList<>();
        for (JsonElement a : applied) {
            JsonObject o = a.getAsJsonObject();
            if (Result.isOk(o)) out.add(new String[] {o.get("in").getAsString(), o.get("where").getAsString()});
        }
        return out;
    }
}
