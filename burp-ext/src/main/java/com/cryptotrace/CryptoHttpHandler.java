package com.cryptotrace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonObject;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Requests carrying "X-CT-Plain: 1" are encrypted right before they leave Burp (Repeater, Intruder, Scanner...).
 * If encryption fails the request is NOT sent in plaintext: it is diverted to a closed local port and annotated.
 * Responses to requests we encrypted are decrypted for the tool (never for Proxy, so the browser gets the original).
 */
public final class CryptoHttpHandler implements HttpHandler {
    /** Discard port on loopback: the connection fails locally, nothing reaches the target. */
    private static final HttpService BLACKHOLE = HttpService.httpService("127.0.0.1", 9, false);
    public static final String DECRYPTED_MARKER = "X-CT-Decrypted";

    private final MontoyaApi api;
    private final Crypto crypto;
    private final Settings settings;
    private final ServerClient server;
    private final SessionKeys sessionKeys;
    /** Plain originals of requests we encrypted, until their response arrives. Entries whose response never
     *  comes (connection error, dropped by Intruder/Scanner) are pruned so they can't pile up in the heap. */
    private final Map<Integer, Pending> encryptedPlain = new ConcurrentHashMap<>();
    private static final int PRUNE_ABOVE = 256;
    private static final long PENDING_TTL_MS = 5 * 60_000L;

    private record Pending(HttpRequest plain, long at) {}

    public CryptoHttpHandler(MontoyaApi api, Crypto crypto, Settings settings, ServerClient server, SessionKeys sessionKeys) {
        this.api = api;
        this.crypto = crypto;
        this.settings = settings;
        this.server = server;
        this.sessionKeys = sessionKeys;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        if (!req.hasHeader(Crypto.PLAIN_MARKER)) return RequestToBeSentAction.continueWith(req);
        String why;
        try {
            Crypto.Result<HttpRequest> enc = crypto.encryptRequest(req);
            if (enc.matched() != null && enc.allOk()) {
                remember(req);
                List<String[]> where = Crypto.appliedLocations(enc.applied());
                api.logging().logToOutput("CryptoTrace encrypted " + req.method() + " " + req.url() + " [" + enc.matched() + "] "
                        + (where.isEmpty() ? "nothing (no apply rule matched this request; sent unchanged)"
                                : String.join(", ", where.stream().map(w -> w[0] + " " + w[1]).toList())));
                return RequestToBeSentAction.continueWith(enc.message());
            }
            why = enc.matched() == null ? "no profile matches this host/path" : enc.errors();
        } catch (ServerClient.ServerException | RuntimeException e) {
            // Any failure -- including a bug or a malformed server reply -- must block: a throw out of this
            // handler could let Burp send the request as it is, i.e. in plaintext.
            why = Crypto.reason(e);
        }
        String note = "CryptoTrace BLOCKED (not sent): " + why;
        api.logging().logToError(note + " - " + req.url());
        // Intruder/Scanner hide annotations by default: also tell the CryptoTrace tab (repeats folded into a count)
        java.util.function.Consumer<String> sink = blockedSink;
        if (sink != null) sink.accept(why);
        return RequestToBeSentAction.continueWith(req.withService(BLACKHOLE), req.annotations().withNotes(note));
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived res) {
        captureSessionKeys(res); // runs for every tool, Proxy included (the handshake is in the browser)
        Pending plain = encryptedPlain.remove(res.messageId());
        if (plain == null || !settings.decryptResponses() || res.toolSource().isFromTool(ToolType.PROXY)) {
            return ResponseReceivedAction.continueWith(res);
        }
        try {
            Crypto.Result<HttpResponse> dec = crypto.decryptResponse(res.initiatingRequest(), res);
            if (dec.matched() == null) return ResponseReceivedAction.continueWith(res);
            if (!dec.allOk()) {
                logRateLimited("CryptoTrace response not decrypted (shown as received): " + dec.errors());
                return ResponseReceivedAction.continueWith(res);
            }
            return ResponseReceivedAction.continueWith(dec.message().withAddedHeader(DECRYPTED_MARKER, "1"));
        } catch (ServerClient.ServerException | RuntimeException e) {
            logRateLimited("CryptoTrace response decrypt failed: " + Crypto.reason(e));
            return ResponseReceivedAction.continueWith(res);
        }
    }

    /** Called with the reason of every blocked request (the CryptoTrace tab shows them). */
    private volatile java.util.function.Consumer<String> blockedSink;

    public void onBlocked(java.util.function.Consumer<String> sink) {
        this.blockedSink = sink;
    }

    private final Map<String, Long> lastLogged = new ConcurrentHashMap<>();

    /** The same message at most once per 30 s (an Intruder run would otherwise flood the error log). */
    private void logRateLimited(String msg) {
        long now = System.currentTimeMillis();
        Long prev = lastLogged.get(msg);
        if (prev != null && now - prev < 30_000) return;
        if (lastLogged.size() > 200) lastLogged.clear();
        lastLogged.put(msg, now);
        api.logging().logToError(msg);
    }

    private void remember(HttpRequestToBeSent req) {
        long now = System.currentTimeMillis();
        if (encryptedPlain.size() > PRUNE_ABOVE) encryptedPlain.values().removeIf(p -> now - p.at() > PENDING_TTL_MS);
        // still too many (a fast Intruder run whose responses never come): drop the oldest
        while (encryptedPlain.size() > PRUNE_ABOVE * 4) {
            encryptedPlain.entrySet().stream().min(java.util.Comparator.comparingLong(e -> e.getValue().at()))
                    .ifPresent(e -> encryptedPlain.remove(e.getKey()));
        }
        encryptedPlain.put(req.messageId(), new Pending(req, now));
    }

    /** Extract any configured session keys from this response and push them to the server. */
    private void captureSessionKeys(HttpResponseReceived res) {
        if (sessionKeys.isEmpty()) return;
        String url = res.initiatingRequest() != null ? res.initiatingRequest().url() : null;
        if (!sessionKeys.mayCapture(url)) return; // don't turn every response body into a String
        List<SessionKeys.Capture> found;
        try {
            found = sessionKeys.extract(url, Utf8.text(res.body().getBytes()), res::headerValue);
        } catch (RuntimeException e) {
            return; // never let capture disturb the response pipeline
        }
        for (SessionKeys.Capture c : found) {
            try {
                JsonObject args = new JsonObject();
                args.addProperty("profile", c.profile());
                args.addProperty("keyName", c.keyName());
                args.addProperty("value", c.value());
                server.call("key", args);
                api.logging().logToOutput("CryptoTrace captured session key " + c.profile() + "." + c.keyName());
            } catch (ServerClient.ServerException e) {
                sessionKeys.pushFailed(c); // retry this value on the next matching response
                api.logging().logToError("CryptoTrace session-key update failed: " + e.getMessage());
            }
        }
    }
}
