package com.cryptotrace;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression: "health failed: crypto server exited" with no reason shown. */
class StartupDiagnosticsTest {
    private static final Path ROOT = Path.of(System.getProperty("cryptotrace.root", ".."));

    @Test
    void unquotesCopyAsPath() {
        assertEquals("C:\\a b\\main.mjs", Settings.unquote("  \"C:\\a b\\main.mjs\" "));
        assertEquals("x", Settings.unquote("'x'"));
        assertEquals("", Settings.unquote(null));
    }

    @Test
    void preflightCatchesEmptyOrMissingScriptAndConfigs() {
        assertTrue(SettingsTab.preflight("node", "", List.of()).contains("empty"));
        assertTrue(SettingsTab.preflight("C:\\nodejs\\node.exe", "C:\\nope\\main.mjs", List.of()).contains("not found"));
        String script = ROOT.resolve("server/src/main.mjs").toString();
        assertTrue(SettingsTab.preflight("node", script, List.of("C:\\nope.json")).contains("Config not found"));
        assertNull(SettingsTab.preflight("node", script, List.of(ROOT.resolve("samples/configs/scenario-a.json").toString())));
    }

    @Test
    void exitReasonIncludesNodeError() throws Exception {
        try (ServerClient c = new ServerClient(l -> { }, 5000)) {
            c.start(ServerClient.command("node", ROOT.resolve("does-not-exist.mjs").toString()));
            ServerClient.ServerException e = assertThrows(ServerClient.ServerException.class, () -> c.call("health", null));
            assertTrue(e.getMessage().contains("code 1") || e.getMessage().contains("not running"), e.getMessage());
            if (e.getMessage().contains("code 1")) assertTrue(e.getMessage().contains("Cannot find module"), e.getMessage());
        }
    }
}
