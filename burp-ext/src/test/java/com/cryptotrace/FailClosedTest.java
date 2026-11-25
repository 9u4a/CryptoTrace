package com.cryptotrace;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A malformed server reply must turn into a block reason, never an exception that lets plaintext out. */
class FailClosedTest {
    private static Crypto.Result<Object> result(String applied) {
        return new Crypto.Result<>("p", null, JsonParser.parseString(applied).getAsJsonArray());
    }

    @Test
    void missingErrorKeyStillGivesAReason() {
        Crypto.Result<Object> r = result("[{\"in\":\"json\",\"where\":\"$.d\",\"ok\":false}]");
        assertFalse(r.allOk());
        assertEquals("json $.d: unknown error; ", r.errors());
    }

    @Test
    void missingOkCountsAsFailure() {
        Crypto.Result<Object> r = result("[{\"in\":\"json\",\"where\":\"$.d\"}]");
        assertFalse(r.allOk());
        assertTrue(r.errors().length() > 0);
    }

    @Test
    void allOkWhenEveryEntryOk() {
        assertTrue(result("[{\"in\":\"json\",\"where\":\"$.d\",\"ok\":true}]").allOk());
        assertTrue(new Crypto.Result<>("p", null, new JsonArray()).allOk());
    }

    @Test
    void describeNeverEmpty() {
        assertEquals("NullPointerException", Crypto.reason(new NullPointerException()));
        assertEquals("boom", Crypto.reason(new IllegalStateException("boom")));
    }
}
