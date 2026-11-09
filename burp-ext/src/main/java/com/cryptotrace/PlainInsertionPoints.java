package com.cryptotrace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;

/**
 * Scanner insertion points INSIDE encrypted values. Each point builds a plaintext request with the payload
 * and the X-CT-Plain marker; CryptoHttpHandler encrypts it on the way out.
 */
public final class PlainInsertionPoints implements AuditInsertionPointProvider {
    private final MontoyaApi api;
    private final Crypto crypto;

    public PlainInsertionPoints(MontoyaApi api, Crypto crypto) {
        this.api = api;
        this.crypto = crypto;
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse base) {
        List<AuditInsertionPoint> out = new ArrayList<>();
        Crypto.Result<HttpRequest> dec;
        try {
            dec = crypto.decryptRequest(base.request());
        } catch (ServerClient.ServerException e) {
            return out;
        }
        if (dec.matched() == null) return out;
        HttpRequest plain = dec.message().withAddedHeader(Crypto.PLAIN_MARKER, "1");

        for (String[] loc : Crypto.appliedLocations(dec.applied())) {
            String in = loc[0];
            String where = loc[1];
            try {
                switch (in) {
                    case "json" -> jsonPoints(plain, JsonPaths.parse(where), out);
                    case "body" -> {
                        if (!jsonPoints(plain, List.of(), out)) out.add(new BodyPoint(plain));
                    }
                    case "header" -> out.add(new HeaderPoint(plain, where));
                    case "query" -> out.add(new QueryPoint(plain, where));
                    default -> { }
                }
            } catch (RuntimeException e) {
                api.logging().logToError("CryptoTrace insertion points (" + in + " " + where + "): " + e.getMessage());
            }
        }
        return out;
    }

    /** Adds one point per scalar leaf under prefix; returns false if the body isn't JSON. */
    private static boolean jsonPoints(HttpRequest plain, List<Object> prefix, List<AuditInsertionPoint> out) {
        JsonElement root;
        try {
            root = JsonParser.parseString(plain.bodyToString());
        } catch (RuntimeException e) {
            return false;
        }
        if (root == null || root.isJsonPrimitive() || root.isJsonNull()) return false;
        for (List<Object> leaf : JsonPaths.leaves(root, prefix)) out.add(new JsonLeafPoint(plain, root, leaf));
        return true;
    }

    private abstract static class Point implements AuditInsertionPoint {
        final HttpRequest plain;

        Point(HttpRequest plain) {
            this.plain = plain;
        }

        @Override
        public List<Range> issueHighlights(ByteArray payload) {
            return List.of(); // offsets in plaintext don't map onto the encrypted wire request
        }
    }

    private static final class JsonLeafPoint extends Point {
        private final JsonElement root;
        private final List<Object> path;

        JsonLeafPoint(HttpRequest plain, JsonElement root, List<Object> path) {
            super(plain);
            this.root = root;
            this.path = path;
        }

        @Override
        public String name() {
            return "CryptoTrace " + JsonPaths.format(path);
        }

        @Override
        public String baseValue() {
            return JsonPaths.get(root, path).getAsString();
        }

        @Override
        public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
            JsonElement copy = root.deepCopy();
            JsonPaths.set(copy, path, new JsonPrimitive(payload.toString()));
            return plain.withBody(ServerClient.GSON.toJson(copy));
        }
    }

    private static final class BodyPoint extends Point {
        BodyPoint(HttpRequest plain) {
            super(plain);
        }

        @Override
        public String name() {
            return "CryptoTrace body";
        }

        @Override
        public String baseValue() {
            return plain.bodyToString();
        }

        @Override
        public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
            return plain.withBody(payload);
        }
    }

    private static final class HeaderPoint extends Point {
        private final String header;

        HeaderPoint(HttpRequest plain, String header) {
            super(plain);
            this.header = header;
        }

        @Override
        public String name() {
            return "CryptoTrace header " + header;
        }

        @Override
        public String baseValue() {
            String v = plain.headerValue(header);
            return v == null ? "" : v;
        }

        @Override
        public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
            return plain.withUpdatedHeader(header, payload.toString());
        }
    }

    private static final class QueryPoint extends Point {
        private final String param;

        QueryPoint(HttpRequest plain, String param) {
            super(plain);
            this.param = param;
        }

        @Override
        public String name() {
            return "CryptoTrace query " + param;
        }

        @Override
        public String baseValue() {
            HttpParameter p = plain.parameter(param, HttpParameterType.URL);
            return p == null ? "" : api_urlDecode(p.value());
        }

        @Override
        public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
            String encoded = java.net.URLEncoder.encode(payload.toString(), java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20");
            return plain.withUpdatedParameters(HttpParameter.urlParameter(param, encoded));
        }

        private static String api_urlDecode(String v) {
            try {
                return java.net.URLDecoder.decode(v, java.nio.charset.StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return v;
            }
        }
    }
}
