package com.cryptotrace;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Child-process client for the local crypto server (server/src/main.mjs), JSON-lines over stdio.
 * Montoya-free so it can be tested without Burp.
 */
public final class ServerClient implements AutoCloseable {
    public static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();

    private final Map<Integer, CompletableFuture<JsonObject>> pending = new ConcurrentHashMap<>();
    private final AtomicInteger seq = new AtomicInteger();
    private final Consumer<String> log;
    private final long timeoutMs;
    private Process process;
    private OutputStream stdin;

    public ServerClient(Consumer<String> log, long timeoutMs) {
        this.log = log;
        this.timeoutMs = timeoutMs;
    }

    /** Start `<command...> ` (e.g. ["node", "/path/server/src/main.mjs"] or ["crypto-server.exe"]). */
    public synchronized void start(List<String> command) throws IOException {
        close();
        ProcessBuilder pb = new ProcessBuilder(command);
        process = pb.start();
        stdin = process.getOutputStream();
        Process p = process;
        Thread out = new Thread(() -> readLoop(p), "cryptotrace-server-out");
        Thread err = new Thread(() -> errLoop(p), "cryptotrace-server-err");
        out.setDaemon(true);
        err.setDaemon(true);
        out.start();
        err.start();
    }

    public synchronized boolean isRunning() {
        return process != null && process.isAlive();
    }

    private void readLoop(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                try {
                    JsonObject msg = GSON.fromJson(line, JsonObject.class);
                    if (msg.has("id") && !msg.get("id").isJsonNull()) {
                        CompletableFuture<JsonObject> f = pending.remove(msg.get("id").getAsInt());
                        if (f != null) f.complete(msg);
                    }
                } catch (RuntimeException e) {
                    log.accept("bad line from server: " + line);
                }
            }
        } catch (IOException ignored) {
            // process ended
        }
        IOException gone = new IOException("crypto server exited");
        pending.values().forEach(f -> f.completeExceptionally(gone));
        pending.clear();
    }

    private void errLoop(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) log.accept(line);
        } catch (IOException ignored) {
            // process ended
        }
    }

    /** Send one op and wait for its reply. Throws on transport failure, timeout, or {"ok": false}. */
    public JsonObject call(String op, JsonObject args) throws ServerException {
        if (!isRunning()) throw new ServerException("crypto server is not running");
        int id = seq.incrementAndGet();
        JsonObject req = args == null ? new JsonObject() : args.deepCopy();
        req.addProperty("id", id);
        req.addProperty("op", op);
        CompletableFuture<JsonObject> f = new CompletableFuture<>();
        pending.put(id, f);
        try {
            byte[] line = (GSON.toJson(req) + "\n").getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                stdin.write(line);
                stdin.flush();
            }
            JsonObject res = f.get(timeoutMs, TimeUnit.MILLISECONDS);
            if (!res.has("ok") || !res.get("ok").getAsBoolean()) {
                throw new ServerException(res.has("error") ? res.get("error").getAsString() : "server error");
            }
            return res;
        } catch (ServerException e) {
            throw e;
        } catch (java.util.concurrent.TimeoutException e) {
            throw new ServerException(op + " timed out after " + timeoutMs + " ms");
        } catch (Exception e) {
            throw new ServerException(op + " failed: " + e.getMessage());
        } finally {
            pending.remove(id);
        }
    }

    public JsonObject load(List<String> files) throws ServerException {
        JsonObject args = new JsonObject();
        JsonArray arr = new JsonArray();
        files.forEach(arr::add);
        args.add("files", arr);
        return call("load", args);
    }

    @Override
    public synchronized void close() {
        if (process != null) {
            try {
                stdin.close();
            } catch (IOException ignored) {
                // already closed
            }
            process.destroy();
            try {
                if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
            process = null;
        }
    }

    public static List<String> command(String launcher, String script) {
        List<String> cmd = new ArrayList<>();
        cmd.add(launcher);
        if (script != null && !script.isBlank()) cmd.add(script);
        return cmd;
    }

    public static final class ServerException extends Exception {
        public ServerException(String msg) {
            super(msg);
        }
    }
}
