package com.cryptotrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runtime session-key capture. The server reports, per profile, which responses carry a
 * session key (urlRegex + jsonPath/regex/header); this matches live responses and yields the
 * values to push back with the "key" op so later requests encrypt/decrypt with the fresh key.
 * Montoya-free so it can be unit-tested without Burp.
 */
public final class SessionKeys {
    public record Rule(String profile, String keyName, Pattern urlRegex, List<Object> jsonParts, Pattern regex, String header) {}
    public record Capture(String profile, String keyName, String value) {}

    private volatile List<Rule> rules = List.of();
    private final Map<String, String> lastPushed = new ConcurrentHashMap<>();

    public boolean isEmpty() {
        return rules.isEmpty();
    }

    public int size() {
        return rules.size();
    }

    /** Replace all rules from a server `load` result: {results:[{profile, captures:[{keyName, urlRegex, ...}]}]}. */
    public void setRules(JsonObject loadResult) {
        List<Rule> next = new ArrayList<>();
        JsonArray results = loadResult == null ? null : loadResult.getAsJsonArray("results");
        if (results != null) {
            for (JsonElement r : results) {
                JsonObject o = r.getAsJsonObject();
                if (o.has("error") || !o.has("captures") || o.get("captures").isJsonNull()) continue;
                String profile = o.get("profile").getAsString();
                for (JsonElement c : o.getAsJsonArray("captures")) {
                    JsonObject cap = c.getAsJsonObject();
                    String jp = str(cap, "jsonPath");
                    next.add(new Rule(
                            profile,
                            cap.get("keyName").getAsString(),
                            str(cap, "urlRegex") != null ? Pattern.compile(str(cap, "urlRegex")) : null,
                            jp != null ? JsonPaths.parse(jp) : null,
                            str(cap, "regex") != null ? Pattern.compile(str(cap, "regex")) : null,
                            str(cap, "header")));
                }
            }
        }
        rules = next;
        lastPushed.clear();
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
    }

    /** Values found in this response, deduped against the last pushed value per (profile,key). */
    public List<Capture> extract(String url, String body, Function<String, String> header) {
        if (rules.isEmpty()) return List.of();
        List<Capture> out = new ArrayList<>();
        for (Rule r : rules) {
            if (r.urlRegex() != null && (url == null || !r.urlRegex().matcher(url).find())) continue;
            String value = valueFor(r, body, header);
            if (value == null || value.isEmpty()) continue;
            String tag = r.profile() + "\u0000" + r.keyName();
            if (value.equals(lastPushed.get(tag))) continue; // same key already pushed
            lastPushed.put(tag, value);
            out.add(new Capture(r.profile(), r.keyName(), value));
        }
        return out;
    }

    /** The server rejected or never got this capture: forget it so the same value is pushed again next time. */
    public void pushFailed(Capture c) {
        lastPushed.remove(c.profile() + "\u0000" + c.keyName(), c.value());
    }

    private static String valueFor(Rule r, String body, Function<String, String> header) {
        try {
            if (r.header() != null) return header == null ? null : header.apply(r.header());
            if (r.jsonParts() != null) {
                JsonElement v = JsonPaths.get(ServerClient.GSON.fromJson(body, JsonElement.class), r.jsonParts());
                return v != null && v.isJsonPrimitive() ? v.getAsString() : null;
            }
            if (r.regex() != null) {
                Matcher m = r.regex().matcher(body == null ? "" : body);
                if (m.find()) return m.groupCount() >= 1 ? m.group(1) : m.group(0);
            }
        } catch (RuntimeException ignored) {
            // malformed body / not JSON: nothing to capture from this response
        }
        return null;
    }
}
