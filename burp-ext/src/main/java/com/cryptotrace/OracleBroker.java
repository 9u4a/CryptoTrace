package com.cryptotrace;

import com.google.gson.JsonObject;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * L4 browser oracle broker. The crypto server asks for a value only the page can compute ({"oracle": {...}} on
 * stdout); the DevTools panel long-polls the bridge for those jobs, runs the page's own function and posts the
 * result back. This class sits in between. It is an ACTIVE feature (it runs page code): off by default, one job
 * at a time, at most one per minIntervalMs. Montoya-free for unit tests.
 */
public final class OracleBroker {
    /** Answers the crypto server: {"oracleResult": oid, ok, value | error}. */
    public interface Replier {
        void reply(int oid, boolean ok, String value, String error);
    }

    static final long BROWSER_GONE_MS = 30_000; // no poll for this long = no browser
    static final long STALE_MS = 7_000;         // the server gives up after 8 s

    private record Job(JsonObject json, long at) {}

    /** Guarded by itself. A job waits here until a panel inspecting the job's origin polls (several tabs may poll). */
    private final ArrayDeque<Job> queue = new ArrayDeque<>();
    private final Replier replier;
    private final LongSupplier clock;
    private volatile boolean enabled;
    private volatile long minIntervalMs = 100;
    private volatile long lastPoll = Long.MIN_VALUE / 2;
    private long lastHanded = Long.MIN_VALUE / 2;

    public OracleBroker(Replier replier) {
        this(replier, () -> System.nanoTime() / 1_000_000);
    }

    OracleBroker(Replier replier, LongSupplier clockMs) {
        this.replier = replier;
        this.clock = clockMs;
    }

    public void enabled(boolean on) {
        enabled = on;
        if (!on) drain("the browser oracle was turned off in Burp");
    }

    public boolean enabled() {
        return enabled;
    }

    public void minIntervalMs(long ms) {
        minIntervalMs = Math.max(0, ms);
    }

    /** True when a panel polled recently. */
    public boolean browserConnected() {
        return clock.getAsLong() - lastPoll < BROWSER_GONE_MS;
    }

    /** A job from the crypto server. Answered at once with an error when the oracle can't run it. */
    public void submit(JsonObject oracle) {
        int oid = oracle.get("oid").getAsInt();
        if (!enabled) {
            replier.reply(oid, false, null, "the browser oracle is off in Burp (CryptoTrace > Options)");
            return;
        }
        if (!browserConnected()) {
            replier.reply(oid, false, null, "no browser is connected (DevTools CryptoTrace panel open, oracle switch on?)");
            return;
        }
        synchronized (queue) {
            queue.add(new Job(oracle, clock.getAsLong()));
            queue.notifyAll();
        }
    }

    /** "scheme://host[:port]" of a page URL, or "" when it has none. */
    static String originOf(String url) {
        if (url == null || url.isBlank()) return "";
        try {
            java.net.URI u = new java.net.URI(url.strip());
            if (u.getScheme() == null || u.getHost() == null) return "";
            return u.getScheme().toLowerCase() + "://" + u.getHost().toLowerCase() + (u.getPort() >= 0 ? ":" + u.getPort() : "");
        } catch (java.net.URISyntaxException e) {
            return "";
        }
    }

    /** A job is for a panel when the page it was traced on has the panel's origin (or either side doesn't say). */
    private static boolean forOrigin(Job j, String origin) {
        if (origin == null || origin.isEmpty()) return true;
        String f = j.json().has("frame") && !j.json().get("frame").isJsonNull() ? originOf(j.json().get("frame").getAsString()) : "";
        return f.isEmpty() || f.equals(originOf(origin));
    }

    public JsonObject next(long waitMs) throws InterruptedException {
        return next(waitMs, null);
    }

    /** The next job for the polling browser, waiting up to waitMs; null when none. Paces jobs by minIntervalMs. */
    /** Like next(waitMs), for the panel inspecting `origin`: jobs traced on another origin stay for that tab. */
    public JsonObject next(long waitMs, String origin) throws InterruptedException {
        lastPoll = clock.getAsLong();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMs);
        Job j = null;
        synchronized (queue) {
            while (j == null) {
                long now = clock.getAsLong();
                for (Iterator<Job> it = queue.iterator(); it.hasNext(); ) {
                    Job q = it.next();
                    if (now - q.at() > STALE_MS) {
                        it.remove();
                        String f = q.json().has("frame") && !q.json().get("frame").isJsonNull() ? originOf(q.json().get("frame").getAsString()) : "";
                        replier.reply(q.json().get("oid").getAsInt(), false, null, "the browser did not pick the job up in time"
                                + (f.isEmpty() ? "" : " (is a DevTools CryptoTrace panel open on " + f + " with the oracle on?)"));
                    } else if (j == null && forOrigin(q, origin)) {
                        it.remove();
                        j = q;
                    }
                }
                if (j != null) break;
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    lastPoll = clock.getAsLong();
                    return null;
                }
                queue.wait(Math.max(1, TimeUnit.NANOSECONDS.toMillis(left)));
                lastPoll = clock.getAsLong();
            }
        }
        synchronized (this) {
            long wait = lastHanded + minIntervalMs - clock.getAsLong();
            if (wait > 0) Thread.sleep(wait);
            lastHanded = clock.getAsLong();
        }
        return j.json();
    }

    /** The browser's answer for job oid. */
    public void complete(int oid, boolean ok, String value, String error) {
        replier.reply(oid, ok, value, ok ? null : (error == null ? "the page function failed" : error));
    }

    private void drain(String why) {
        synchronized (queue) {
            Job j;
            while ((j = queue.poll()) != null) replier.reply(j.json().get("oid").getAsInt(), false, null, why);
        }
    }
}
