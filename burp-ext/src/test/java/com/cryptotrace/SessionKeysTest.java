package com.cryptotrace;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionKeysTest {
    private static JsonObject loadResult(String captures) {
        return JsonParser.parseString(
                "{\"results\":[{\"profile\":\"p\",\"selftest\":[]," + captures + "}]}").getAsJsonObject();
    }

    @Test
    void extractsByJsonPathAndDedupes() {
        SessionKeys sk = new SessionKeys();
        sk.setRules(loadResult("\"captures\":[{\"keyName\":\"sk\",\"urlRegex\":\"/auth/handshake\",\"jsonPath\":\"$.data.key\"}]"));
        assertEquals(1, sk.size());

        String body = "{\"data\":{\"key\":\"ABC123\"}}";
        List<SessionKeys.Capture> first = sk.extract("https://api.test/auth/handshake", body, n -> null);
        assertEquals(1, first.size());
        assertEquals("p", first.get(0).profile());
        assertEquals("sk", first.get(0).keyName());
        assertEquals("ABC123", first.get(0).value());

        // Same value again -> no re-push.
        assertTrue(sk.extract("https://api.test/auth/handshake", body, n -> null).isEmpty());
        // New value -> pushed.
        List<SessionKeys.Capture> changed = sk.extract("https://api.test/auth/handshake", "{\"data\":{\"key\":\"XYZ\"}}", n -> null);
        assertEquals("XYZ", changed.get(0).value());
    }

    @Test
    void failedPushIsRetriedOnNextResponse() {
        SessionKeys sk = new SessionKeys();
        sk.setRules(loadResult("\"captures\":[{\"keyName\":\"sk\",\"jsonPath\":\"$.key\"}]"));
        String body = "{\"key\":\"K1\"}";
        List<SessionKeys.Capture> first = sk.extract("https://api.test/x", body, n -> null);
        sk.pushFailed(first.get(0));
        assertEquals("K1", sk.extract("https://api.test/x", body, n -> null).get(0).value());
        assertTrue(sk.extract("https://api.test/x", body, n -> null).isEmpty());
    }

    @Test
    void urlRegexGatesCaptureAndMissingPathYieldsNothing() {
        SessionKeys sk = new SessionKeys();
        sk.setRules(loadResult("\"captures\":[{\"keyName\":\"sk\",\"urlRegex\":\"/auth/handshake\",\"jsonPath\":\"$.key\"}]"));
        assertTrue(sk.extract("https://api.test/other", "{\"key\":\"ABC\"}", n -> null).isEmpty());
        assertTrue(sk.extract("https://api.test/auth/handshake", "{\"nope\":1}", n -> null).isEmpty());
    }

    @Test
    void extractsFromHeaderAndRegex() {
        SessionKeys sk = new SessionKeys();
        sk.setRules(loadResult("\"captures\":[{\"keyName\":\"h\",\"header\":\"X-Session-Key\"}]"));
        List<SessionKeys.Capture> h = sk.extract("https://api.test/x", "", Map.of("X-Session-Key", "HVAL")::get);
        assertEquals("HVAL", h.get(0).value());

        SessionKeys rx = new SessionKeys();
        rx.setRules(loadResult("\"captures\":[{\"keyName\":\"r\",\"regex\":\"sessionKey=([A-Z0-9]+)\"}]"));
        List<SessionKeys.Capture> m = rx.extract("https://api.test/x", "var x='sessionKey=KEY42';", n -> null);
        assertEquals("KEY42", m.get(0).value());
    }

    @Test
    void noRulesMeansEmpty() {
        SessionKeys sk = new SessionKeys();
        assertTrue(sk.isEmpty());
        assertTrue(sk.extract("https://api.test/x", "{}", n -> null).isEmpty());
        sk.setRules(loadResult("\"captures\":[]"));
        assertTrue(sk.isEmpty());
    }
}
