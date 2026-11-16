package com.cryptotrace;

import burp.api.montoya.persistence.Preferences;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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
        SettingsTab tab = new SettingsTab(settings, new ServerClient(line -> { }, 1000), new SessionKeys());
        assertNotNull(tab.component());
        assertNotNull(store.get("cryptotrace.bridge.token"), "token generated once and persisted");
    }
}
