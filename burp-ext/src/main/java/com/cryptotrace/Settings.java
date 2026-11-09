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
        String v = prefs.getString(LAUNCHER);
        return v == null || v.isBlank() ? "node" : v;
    }

    public void launcher(String v) {
        prefs.setString(LAUNCHER, v.trim());
    }

    /** Path to server/src/main.mjs when launching through node; empty for the packaged exe. */
    public String script() {
        String v = prefs.getString(SCRIPT);
        return v == null ? "" : v;
    }

    public void script(String v) {
        prefs.setString(SCRIPT, v.trim());
    }

    public List<String> configs() {
        String v = prefs.getString(CONFIGS);
        if (v == null || v.isBlank()) return List.of();
        return Arrays.stream(v.split("\n")).map(String::trim).filter(s -> !s.isEmpty()).toList();
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
