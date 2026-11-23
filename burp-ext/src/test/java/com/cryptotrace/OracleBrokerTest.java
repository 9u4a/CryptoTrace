package com.cryptotrace;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The L4 oracle broker between the crypto server (stdio) and the browser panel (bridge long-poll). */
class OracleBrokerTest {
    private final List<String> replies = new ArrayList<>();
    private final OracleBroker broker = new OracleBroker((oid, ok, value, error) -> replies.add(oid + ":" + ok + ":" + (ok ? value : error)));

    private static JsonObject job(int oid, String value) {
        return JsonParser.parseString("{\"oid\":" + oid + ",\"fn\":\"scramble@http://app.test/a.js:3:1\",\"frame\":\"http://app.test/\",\"dir\":\"encrypt\",\"value\":\"" + value + "\"}").getAsJsonObject();
    }

    @Test
    void offByDefaultAnswersAtOnce() {
        broker.submit(job(1, "x"));
        assertEquals(1, replies.size());
        assertTrue(replies.get(0).startsWith("1:false:"));
        assertTrue(replies.get(0).contains("off"), replies.get(0));
    }

    @Test
    void noBrowserPollingAnswersAtOnce() {
        broker.enabled(true);
        broker.submit(job(2, "x"));
        assertTrue(replies.get(0).startsWith("2:false:") && replies.get(0).contains("browser"), replies.get(0));
    }

    @Test
    void jobGoesToThePollingBrowserAndItsResultBack() throws Exception {
        broker.enabled(true);
        broker.minIntervalMs(0);
        assertNull(broker.next(10), "nothing queued yet (and the browser now counts as connected)");
        broker.submit(job(3, "hello"));
        JsonObject j = broker.next(1000);
        assertNotNull(j);
        assertEquals(3, j.get("oid").getAsInt());
        assertEquals("hello", j.get("value").getAsString());
        broker.complete(3, true, "c2NyYW1ibGVk", null);
        assertEquals(List.of("3:true:c2NyYW1ibGVk"), replies);
    }

    @Test
    void jobsArePacedByTheMinimumInterval() throws Exception {
        broker.enabled(true);
        broker.minIntervalMs(150);
        broker.next(1);
        broker.submit(job(4, "a"));
        broker.submit(job(5, "b"));
        long t0 = System.nanoTime();
        broker.next(1000);
        broker.next(1000);
        assertTrue((System.nanoTime() - t0) / 1_000_000 >= 140, "second job waits for the interval");
    }

    @Test
    void staleJobsAreAnsweredNotHandedOut() throws Exception {
        long[] now = {1_000_000};
        OracleBroker b = new OracleBroker((oid, ok, value, error) -> replies.add(oid + ":" + ok + ":" + error), () -> now[0]);
        b.enabled(true);
        b.minIntervalMs(0);
        b.next(1);
        b.submit(job(6, "old"));
        now[0] += 20_000; // the server gave up on it long ago
        assertNull(b.next(10));
        assertTrue(replies.get(0).startsWith("6:false:"), replies.toString());
    }
}
