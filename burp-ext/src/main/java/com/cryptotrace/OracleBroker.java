package com.cryptotrace;

import com.google.gson.JsonObject;

import java.util.concurrent.LinkedBlockingQueue;
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

    private final LinkedBlockingQueue<Job> queue = new LinkedBlockingQueue<>();
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
        queue.add(new Job(oracle, clock.getAsLong()));
    }

    /** The next job for the polling browser, waiting up to waitMs; null when none. Paces jobs by minIntervalMs. */
    public JsonObject next(long waitMs) throws InterruptedException {
        lastPoll = clock.getAsLong();
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(waitMs);
        while (true) {
            long left = deadline - System.nanoTime();
            Job j = queue.poll(Math.max(0, left), TimeUnit.NANOSECONDS);
            lastPoll = clock.getAsLong();
            if (j == null) return null;
            if (clock.getAsLong() - j.at() > STALE_MS) {
                replier.reply(j.json().get("oid").getAsInt(), false, null, "the browser did not pick the job up in time");
                continue;
            }
            synchronized (this) {
                long wait = lastHanded + minIntervalMs - clock.getAsLong();
                if (wait > 0) Thread.sleep(wait);
                lastHanded = clock.getAsLong();
            }
            return j.json();
        }
    }

    /** The browser's answer for job oid. */
    public void complete(int oid, boolean ok, String value, String error) {
        replier.reply(oid, ok, value, ok ? null : (error == null ? "the page function failed" : error));
    }

    private void drain(String why) {
        Job j;
        while ((j = queue.poll()) != null) replier.reply(j.json().get("oid").getAsInt(), false, null, why);
    }
}
