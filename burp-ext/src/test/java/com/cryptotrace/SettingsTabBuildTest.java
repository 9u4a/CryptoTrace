package com.cryptotrace;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The suite tab must build without Burp (catches field-initialization-order NPEs before a release). */
class SettingsTabBuildTest {
    @Test
    void buildsHeadless() {
        System.setProperty("java.awt.headless", "true");
        Map<String, Object> store = new HashMap<>();
        Preferences prefs = (Preferences) Proxy.newProxyInstance(Preferences.class.getClassLoader(),
                new Class<?>[]{Preferences.class}, (proxy, m, args) -> {
                    String n = m.getName();
                    if (n.startsWith("set")) { store.put(String.valueOf(args[0]), args[1]); return null; }
                    if (n.startsWith("get")) return store.get(String.valueOf(args[0]));
                    return null;
                });
        Settings settings = new Settings(prefs, "");
        Scopes scopes = new Scopes();
        scopes.set(com.google.gson.JsonParser.parseString(
                "{\"results\":[{\"profile\":\"a\",\"scope\":[{\"host\":\"a.test\",\"port\":null,\"pathRegex\":\".*\"}]}]}").getAsJsonObject());
        SessionKeys keys = new SessionKeys();
        keys.markPushed(new SessionKeys.Capture("a", "sk", "V"));
        SettingsTab tab = new SettingsTab(settings, new ServerClient(line -> { }, 1000), keys, scopes);
        assertNotNull(tab.component());
        assertNotNull(store.get("cryptotrace.bridge.token"), "token generated once and persisted");
        tab.stopServer(); // Stop works even when nothing runs, and leaves no scope or key behind
        assertTrue(scopes.isEmpty());
        assertTrue(keys.pushed().isEmpty());
    }
}
