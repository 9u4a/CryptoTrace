package com.cryptotrace;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Montoya <-> server protocol. Rebuilds messages by diffing headers so HTTP/2 metadata is preserved. */
public final class Crypto {
    public static final String PLAIN_MARKER = "X-CT-Plain";

    private final ServerClient server;

    public Crypto(ServerClient server) {
        this.server = server;
    }

    /** Result of a transform. `matched` is the profile name or null when out of scope. */
    public record Result<T>(String matched, T message, JsonArray applied) {
        public boolean allOk() {
            for (JsonElement a : applied) if (!a.getAsJsonObject().get("ok").getAsBoolean()) return false;
            return true;
        }

        public String errors() {
            StringBuilder sb = new StringBuilder();
            for (JsonElement a : applied) {
                JsonObject o = a.getAsJsonObject();
                if (!o.get("ok").getAsBoolean()) {
                    sb.append(o.get("in").getAsString()).append(' ').append(o.get("where").getAsString())
                            .append(": ").append(o.get("error").getAsString()).append("; ");
                }
            }
            return sb.toString();
        }
    }

    public Result<HttpRequest> decryptRequest(HttpRequest req) throws ServerClient.ServerException {
        return requestOp("decryptRequest", req);
    }

    /** Encrypts every configured location and strips the X-CT-Plain marker. */
    public Result<HttpRequest> encryptRequest(HttpRequest req) throws ServerClient.ServerException {
        return requestOp("encryptRequest", req);
    }

    public Result<HttpResponse> decryptResponse(HttpRequest req, HttpResponse res) throws ServerClient.ServerException {
        return responseOp("decryptResponse", req, res);
    }

    public Result<HttpResponse> encryptResponse(HttpRequest req, HttpResponse res) throws ServerClient.ServerException {
        return responseOp("encryptResponse", req, res);
    }

    private Result<HttpRequest> requestOp(String op, HttpRequest req) throws ServerClient.ServerException {
        JsonObject msg = new JsonObject();
        msg.addProperty("path", req.path());
        msg.add("headers", headersJson(req.headers()));
        msg.addProperty("body", req.bodyToString());
        JsonObject args = target(req);
        args.add("request", msg);
        JsonObject res = server.call(op, args);
        String matched = res.get("matched").isJsonNull() ? null : res.get("matched").getAsString();
        JsonObject out = res.getAsJsonObject("request");
        HttpRequest rebuilt = req;
        if (out.has("path") && !out.get("path").getAsString().equals(req.path())) rebuilt = rebuilt.withPath(out.get("path").getAsString());
        rebuilt = applyHeaders(rebuilt, req.headers(), out.getAsJsonArray("headers"));
        rebuilt = rebuilt.withBody(out.get("body").getAsString());
        return new Result<>(matched, rebuilt, res.getAsJsonArray("applied"));
    }

    private Result<HttpResponse> responseOp(String op, HttpRequest req, HttpResponse resp) throws ServerClient.ServerException {
        JsonObject msg = new JsonObject();
        msg.add("headers", headersJson(resp.headers()));
        msg.addProperty("body", resp.bodyToString());
        JsonObject args = target(req);
        args.addProperty("path", req.path());
        args.add("response", msg);
        JsonObject res = server.call(op, args);
        String matched = res.get("matched").isJsonNull() ? null : res.get("matched").getAsString();
        JsonObject out = res.getAsJsonObject("response");
        HttpResponse rebuilt = resp;
        JsonArray headers = out.getAsJsonArray("headers");
        Map<String, String> want = toMap(headers);
        for (HttpHeader h : resp.headers()) if (!want.containsKey(h.name().toLowerCase())) rebuilt = rebuilt.withRemovedHeader(h.name());
        for (JsonElement e : headers) {
            String n = e.getAsJsonArray().get(0).getAsString();
            String v = e.getAsJsonArray().get(1).getAsString();
            rebuilt = rebuilt.hasHeader(n) ? rebuilt.withUpdatedHeader(n, v) : rebuilt.withAddedHeader(n, v);
        }
        rebuilt = rebuilt.withBody(out.get("body").getAsString());
        return new Result<>(matched, rebuilt, res.getAsJsonArray("applied"));
    }

    private static HttpRequest applyHeaders(HttpRequest req, List<HttpHeader> before, JsonArray after) {
        Map<String, String> want = toMap(after);
        HttpRequest r = req;
        for (HttpHeader h : before) if (!want.containsKey(h.name().toLowerCase())) r = r.withRemovedHeader(h.name());
        for (JsonElement e : after) {
            String n = e.getAsJsonArray().get(0).getAsString();
            String v = e.getAsJsonArray().get(1).getAsString();
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
            pair.add(h.value());
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

    /** Applied entries as simple (in, where) pairs, for insertion-point discovery. */
    public static List<String[]> appliedLocations(JsonArray applied) {
        List<String[]> out = new ArrayList<>();
        for (JsonElement a : applied) {
            JsonObject o = a.getAsJsonObject();
            if (o.get("ok").getAsBoolean()) out.add(new String[] {o.get("in").getAsString(), o.get("where").getAsString()});
        }
        return out;
    }
}
