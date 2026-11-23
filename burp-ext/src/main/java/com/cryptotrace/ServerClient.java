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
    // which process each pending call went to: a dying process fails only its own calls, never the new one's
    private final Map<Integer, Process> pendingProc = new ConcurrentHashMap<>();
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
        stderrTail.clear();
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

    /** Last stderr lines, attached to errors when the process dies. */
    private final java.util.Deque<String> stderrTail = new java.util.concurrent.ConcurrentLinkedDeque<>();

    private void readLoop(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                try {
                    JsonObject msg = GSON.fromJson(line, JsonObject.class);
                    if (msg.has("oracle") && msg.get("oracle").isJsonObject()) { // the server asks for a page-computed value
                        Consumer<JsonObject> sink = oracleSink;
                        int oid = msg.getAsJsonObject("oracle").get("oid").getAsInt();
                        if (sink == null) oracleResult(oid, false, null, "the browser oracle is not available in this Burp");
                        else sink.accept(msg.getAsJsonObject("oracle"));
                        continue;
                    }
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
        IOException gone = new IOException(exitReason(p));
        for (Map.Entry<Integer, Process> e : pendingProc.entrySet()) {
            if (e.getValue() != p) continue; // a call to the restarted (new) process stays pending
            CompletableFuture<JsonObject> f = pending.remove(e.getKey());
            pendingProc.remove(e.getKey());
            if (f != null) f.completeExceptionally(gone);
        }
    }

    private void errLoop(Process p) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                stderrTail.addLast(line);
                while (stderrTail.size() > 40) stderrTail.pollFirst();
                log.accept(line);
            }
        } catch (IOException ignored) {
            // process ended
        }
    }

    /** "crypto server exited (code 1): <last stderr lines>" — waits briefly so stderr is drained. */
    private String exitReason(Process p) {
        try {
            p.waitFor(1, TimeUnit.SECONDS);
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        String code = p.isAlive() ? "?" : String.valueOf(p.exitValue());
        return "crypto server exited (code " + code + ")" + summarize(List.copyOf(stderrTail));
    }

    /** Prefer the first "...Error: ..." line (Node puts the cause there, then a stack); else the last lines. */
    static String summarize(List<String> lines) {
        for (String l : lines) {
            String s = l.strip();
            if (s.matches("^[\\w.]*Error( \\[\\w+])?:.*")) return ": " + s;
        }
        List<String> nonBlank = lines.stream().map(String::strip).filter(s -> !s.isEmpty()).toList();
        if (nonBlank.isEmpty()) return "";
        return ": " + String.join(" | ", nonBlank.subList(Math.max(0, nonBlank.size() - 3), nonBlank.size()));
    }

    /** Send one op and wait for its reply. Throws on transport failure, timeout, or {"ok": false}. */
    public JsonObject call(String op, JsonObject args) throws ServerException {
        if (!isRunning()) throw new ServerException("crypto server is not running");
        int id = seq.incrementAndGet();
        JsonObject req = args == null ? new JsonObject() : args.deepCopy();
        req.addProperty("id", id);
        req.addProperty("op", op);
        CompletableFuture<JsonObject> f = new CompletableFuture<>();
        try {
            byte[] line = (GSON.toJson(req) + "\n").getBytes(StandardCharsets.UTF_8);
            synchronized (this) {
                if (process == null) throw new ServerException("crypto server is not running");
                pending.put(id, f);
                pendingProc.put(id, process);
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
        } catch (java.util.concurrent.ExecutionException e) {
            throw new ServerException(op + " failed: " + e.getCause().getMessage());
        } catch (Exception e) {
            throw new ServerException(op + " failed: " + e.getMessage());
        } finally {
            pending.remove(id);
            pendingProc.remove(id);
        }
    }

    // L4 oracle: questions from the server ({"oracle": {...}} lines) go to this sink (the OracleBroker);
    // answers go back with oracleResult. Must not block (it runs on the stdout reader thread).
    private volatile Consumer<JsonObject> oracleSink;

    public void oracleSink(Consumer<JsonObject> sink) {
        this.oracleSink = sink;
    }

    /** Answer the server's oracle question oid: {"oracleResult": oid, ok, value | error}. */
    public void oracleResult(int oid, boolean ok, String value, String error) {
        JsonObject o = new JsonObject();
        o.addProperty("oracleResult", oid);
        o.addProperty("ok", ok);
        if (ok) o.addProperty("value", value);
        else o.addProperty("error", error);
        byte[] line = (GSON.toJson(o) + "\n").getBytes(StandardCharsets.UTF_8);
        synchronized (this) {
            if (stdin == null) return;
            try {
                stdin.write(line);
                stdin.flush();
            } catch (IOException e) {
                log.accept("oracle answer not delivered: " + e.getMessage());
            }
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
