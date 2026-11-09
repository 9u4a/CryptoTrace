package com.cryptotrace;

import burp.api.montoya.persistence.Preferences;

import java.util.Arrays;
import java.util.List;

/** User settings persisted in Burp preferences (per user, not per project). */
public final class Settings {
    private static final String LAUNCHER = "cryptotrace.launcher";
    private static final String SCRIPT = "cryptotrace.script";
    private static final String CONFIGS = "cryptotrace.configs";
    private static final String DECRYPT_RESPONSES = "cryptotrace.decryptResponses";

    private final Preferences prefs;

    public Settings(Preferences prefs) {
        this.prefs = prefs;
    }

    /** Executable: "node" (or full path to node.exe), or the packaged crypto-server.exe. */
    public String launcher() {
        String v = unquote(prefs.getString(LAUNCHER));
        return v.isEmpty() ? "node" : v;
    }

    public void launcher(String v) {
        prefs.setString(LAUNCHER, unquote(v));
    }

    /** Path to server/src/main.mjs when launching through node; empty for the packaged exe. */
    public String script() {
        return unquote(prefs.getString(SCRIPT));
    }

    public void script(String v) {
        prefs.setString(SCRIPT, unquote(v));
    }

    public List<String> configs() {
        String v = prefs.getString(CONFIGS);
        if (v == null || v.isBlank()) return List.of();
        return Arrays.stream(v.split("\n")).map(Settings::unquote).filter(s -> !s.isEmpty()).toList();
    }

    /** Trim and drop surrounding quotes (Windows "Copy as path" adds them). */
    static String unquote(String v) {
        if (v == null) return "";
        String s = v.trim();
        if (s.length() >= 2 && (s.startsWith("\"") && s.endsWith("\"") || s.startsWith("'") && s.endsWith("'"))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        return s;
    }

    public void configs(List<String> files) {
        prefs.setString(CONFIGS, String.join("\n", files));
    }

    /** Show decrypted responses for requests CryptoTrace encrypted (non-Proxy tools only). Default on. */
    public boolean decryptResponses() {
        Boolean v = prefs.getBoolean(DECRYPT_RESPONSES);
        return v == null || v;
    }

    public void decryptResponses(boolean v) {
        prefs.setBoolean(DECRYPT_RESPONSES, v);
    }
}
