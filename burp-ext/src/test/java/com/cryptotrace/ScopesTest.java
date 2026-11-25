package com.cryptotrace;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScopesTest {
    @Test
    void matchesLikeTheServer() {
        Scopes s = new Scopes();
        long g0 = s.generation();
        s.set(JsonParser.parseString("{\"results\":["
                + "{\"profile\":\"a\",\"scope\":[{\"host\":\"*.bank.test\",\"port\":null,\"pathRegex\":\"^/api/\"}]},"
                + "{\"profile\":\"b\",\"scope\":[{\"host\":\"127.0.0.1\",\"port\":8088,\"pathRegex\":\".*\"}]},"
                + "{\"file\":\"bad.json\",\"error\":\"broken\"}]}").getAsJsonObject());
        assertNotEquals(g0, s.generation());
        assertTrue(s.matches("WWW.Bank.test", 443, "/api/login?x=1"));
        assertTrue(s.matches("bank.test", 80, "/api/x"));
        assertFalse(s.matches("bank.test", 443, "/static/app.js"));
        assertFalse(s.matches("evilbank.test", 443, "/api/x"));
        assertTrue(s.matches("127.0.0.1", 8088, "/"));
        assertFalse(s.matches("127.0.0.1", 9999, "/"));
    }

    @Test
    void emptyUntilLoaded() {
        Scopes s = new Scopes();
        assertTrue(s.isEmpty());
        assertFalse(s.matches("a.test", 443, "/"));
    }
}
