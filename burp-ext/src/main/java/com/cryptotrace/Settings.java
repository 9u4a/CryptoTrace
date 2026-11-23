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
    private static final String BRIDGE_ENABLED = "cryptotrace.bridge.enabled";
    private static final String BRIDGE_PORT = "cryptotrace.bridge.port";
    private static final String BRIDGE_TOKEN = "cryptotrace.bridge.token";

    private final Preferences prefs;
    private final String defaultScript;

    /** extensionJar: Burp's path to our jar, used to find <repo>/server/src/main.mjs when the field is empty. */
    public Settings(Preferences prefs, String extensionJar) {
        this.prefs = prefs;
        this.defaultScript = locateScript(extensionJar);
    }

    /** <repo>/burp-ext/build/libs/cryptotrace-x-all.jar -> <repo>/server/src/main.mjs, if it exists. */
    static String locateScript(String jar) {
        if (jar == null || jar.isBlank()) return "";
        try {
            java.nio.file.Path p = java.nio.file.Path.of(jar).toAbsolutePath().getParent();
            for (int i = 0; i < 5 && p != null; i++, p = p.getParent()) {
                java.nio.file.Path candidate = p.resolve("server").resolve("src").resolve("main.mjs");
                if (java.nio.file.Files.isRegularFile(candidate)) return candidate.toString();
            }
        } catch (RuntimeException ignored) {
            // invalid path
        }
        return "";
    }

    public String defaultScript() {
        return defaultScript;
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
        String v = unquote(prefs.getString(SCRIPT));
        return v.isEmpty() ? defaultScript : v;
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

    private static final String ORACLE_ENABLED = "cryptotrace.oracle.enabled";
    private static final String ORACLE_INTERVAL = "cryptotrace.oracle.intervalMs";

    /** L4 browser oracle: let the page's own function re-encrypt edited fields. ACTIVE (runs page code). Default OFF. */
    public boolean oracleEnabled() {
        Boolean v = prefs.getBoolean(ORACLE_ENABLED);
        return v != null && v;
    }

    public void oracleEnabled(boolean v) {
        prefs.setBoolean(ORACLE_ENABLED, v);
    }

    /** Minimum time between two oracle calls into the page (throttle). Default 100 ms. */
    public int oracleIntervalMs() {
        Integer v = prefs.getInteger(ORACLE_INTERVAL);
        return v == null ? 100 : Math.max(0, v);
    }

    public void oracleIntervalMs(int v) {
        prefs.setInteger(ORACLE_INTERVAL, Math.max(0, v));
    }

    /** Browser bridge on 127.0.0.1 (receive configs from the Chrome extension). Default on. */
    public boolean bridgeEnabled() {
        Boolean v = prefs.getBoolean(BRIDGE_ENABLED);
        return v == null || v;
    }

    public void bridgeEnabled(boolean v) {
        prefs.setBoolean(BRIDGE_ENABLED, v);
    }

    public int bridgePort() {
        Integer v = prefs.getInteger(BRIDGE_PORT);
        return v == null || v < 1 || v > 65535 ? Bridge.DEFAULT_PORT : v;
    }

    public void bridgePort(int v) {
        prefs.setInteger(BRIDGE_PORT, v);
    }

    /** Pairing token, generated once and kept until regenerated (so the browser needs it only once). */
    public synchronized String bridgeToken() {
        String v = prefs.getString(BRIDGE_TOKEN);
        if (v == null || v.isBlank()) v = regenerateBridgeToken();
        return v;
    }

    public synchronized String regenerateBridgeToken() {
        byte[] b = new byte[24];
        new java.security.SecureRandom().nextBytes(b);
        String t = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        prefs.setString(BRIDGE_TOKEN, t);
        return t;
    }
}
