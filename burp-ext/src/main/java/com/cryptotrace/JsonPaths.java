package com.cryptotrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Same JSON path subset as server/src/jsonpath.mjs: $.a.b[0].c and $['a-b']. Montoya-free. */
public final class JsonPaths {
    private static final Pattern TOKEN = Pattern.compile("\\.([A-Za-z_$][\\w$-]*)|\\[(\\d+)]|\\['([^']*)']|\\[\"([^\"]*)\"]");

    private JsonPaths() {}

    /** Path step: String for object keys, Integer for array indices. */
    public static List<Object> parse(String path) {
        if (path == null || !path.startsWith("$")) throw new IllegalArgumentException("JSON path must start with $: " + path);
        List<Object> parts = new ArrayList<>();
        Matcher m = TOKEN.matcher(path);
        int pos = 1;
        while (pos < path.length()) {
            if (!m.find(pos) || m.start() != pos) throw new IllegalArgumentException("bad JSON path: " + path);
            if (m.group(2) != null) parts.add(Integer.parseInt(m.group(2)));
            else parts.add(m.group(1) != null ? m.group(1) : m.group(3) != null ? m.group(3) : m.group(4));
            pos = m.end();
        }
        return parts;
    }

    public static String format(List<Object> parts) {
        StringBuilder sb = new StringBuilder("$");
        for (Object p : parts) {
            if (p instanceof Integer) sb.append('[').append(p).append(']');
            else if (((String) p).matches("[A-Za-z_$][\\w$-]*")) sb.append('.').append(p);
            else sb.append("['").append(p).append("']");
        }
        return sb.toString();
    }

    public static JsonElement get(JsonElement root, List<Object> parts) {
        JsonElement cur = root;
        for (Object p : parts) {
            if (cur == null) return null;
            if (p instanceof Integer i) {
                if (!cur.isJsonArray() || i >= cur.getAsJsonArray().size()) return null;
                cur = cur.getAsJsonArray().get(i);
            } else {
                if (!cur.isJsonObject()) return null;
                cur = cur.getAsJsonObject().get((String) p);
            }
        }
        return cur;
    }

    public static void set(JsonElement root, List<Object> parts, JsonElement value) {
        JsonElement parent = get(root, parts.subList(0, parts.size() - 1));
        Object last = parts.get(parts.size() - 1);
        if (parent instanceof JsonArray a && last instanceof Integer i) a.set(i, value);
        else if (parent instanceof JsonObject o && last instanceof String k) o.add(k, value);
        else throw new IllegalArgumentException("JSON path parent not found: " + format(parts));
    }

    /** All scalar leaves (string/number/boolean) under `prefix`, as absolute paths. */
    public static List<List<Object>> leaves(JsonElement root, List<Object> prefix) {
        List<List<Object>> out = new ArrayList<>();
        walk(get(root, prefix), new ArrayList<>(prefix), out);
        return out;
    }

    private static void walk(JsonElement e, List<Object> path, List<List<Object>> out) {
        if (e == null || e.isJsonNull()) return;
        if (e instanceof JsonPrimitive) {
            out.add(new ArrayList<>(path));
        } else if (e.isJsonObject()) {
            for (var en : e.getAsJsonObject().entrySet()) {
                path.add(en.getKey());
                walk(en.getValue(), path, out);
                path.remove(path.size() - 1);
            }
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) {
                path.add(i);
                walk(a.get(i), path, out);
                path.remove(path.size() - 1);
            }
        }
    }
}
