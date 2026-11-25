package com.cryptotrace;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * The loaded profiles' scopes (host, port, pathRegex), kept in Burp so the editor tabs can tell whether a
 * message is in scope without a round trip to the server on the UI thread. Mirrors server/src/profile.mjs
 * inScope/hostMatch. Montoya-free so it can be unit-tested.
 */
public final class Scopes {
    record Entry(String host, Integer port, Pattern path) {}

    private volatile List<Entry> entries = List.of();
    private volatile long generation;

    /** Replace from a server `load` result: {results:[{scope:[{host, port, pathRegex}]}]}. Failed files are skipped. */
    public void set(JsonObject loadResult) {
        List<Entry> next = new ArrayList<>();
        if (loadResult != null && loadResult.has("results")) {
            for (JsonElement r : loadResult.getAsJsonArray("results")) {
                JsonObject o = r.getAsJsonObject();
                if (o.has("error") || !o.has("scope") || !o.get("scope").isJsonArray()) continue;
                for (JsonElement se : o.getAsJsonArray("scope")) {
                    JsonObject s = se.getAsJsonObject();
                    String host = s.has("host") && !s.get("host").isJsonNull() ? s.get("host").getAsString().toLowerCase(Locale.ROOT) : null;
                    Integer port = s.has("port") && !s.get("port").isJsonNull() ? s.get("port").getAsInt() : null;
                    String re = s.has("pathRegex") && !s.get("pathRegex").isJsonNull() ? s.get("pathRegex").getAsString() : ".*";
                    Pattern p;
                    try {
                        p = Pattern.compile(re);
                    } catch (PatternSyntaxException e) {
                        p = null; // JS-only syntax: let the server decide (treated as in scope here)
                    }
                    next.add(new Entry(host, port, p));
                }
            }
        }
        entries = List.copyOf(next);
        generation++;
    }

    /** Bumped on every set(): cached results from an older config must not be reused. */
    public long generation() {
        return generation;
    }

    public boolean isEmpty() {
        return entries.isEmpty();
    }

    /** `path` may carry a query string; only the path part is matched, as on the server. */
    public boolean matches(String host, int port, String path) {
        String h = host == null ? "" : host.toLowerCase(Locale.ROOT);
        String pathname = path == null ? "" : path.split("[?]", 2)[0];
        for (Entry e : entries) {
            if (!hostMatch(e.host(), h)) continue;
            if (e.port() != null && e.port() != port) continue;
            if (e.path() == null || e.path().matcher(pathname).find()) return true;
        }
        return false;
    }

    static boolean hostMatch(String pattern, String h) {
        if (pattern == null || pattern.isEmpty()) return false;
        if (pattern.equals(h)) return true;
        String base = pattern.startsWith("*.") ? pattern.substring(2) : pattern.startsWith(".") ? pattern.substring(1) : null;
        return base != null && (h.equals(base) || h.endsWith("." + base));
    }
}
