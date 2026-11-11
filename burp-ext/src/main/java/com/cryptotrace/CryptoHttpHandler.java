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
                return RequestToBeSentAction.continueWith(enc.message());
            }
            why = enc.matched() == null ? "no profile matches this host/path" : enc.errors();
        } catch (ServerClient.ServerException e) {
            why = e.getMessage();
        }
        String note = "CryptoTrace BLOCKED (not sent): " + why;
        api.logging().logToError(note + " — " + req.url());
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
            if (dec.matched() == null || !dec.allOk()) return ResponseReceivedAction.continueWith(res);
            return ResponseReceivedAction.continueWith(dec.message().withAddedHeader(DECRYPTED_MARKER, "1"));
        } catch (ServerClient.ServerException e) {
            api.logging().logToError("CryptoTrace response decrypt failed: " + e.getMessage());
            return ResponseReceivedAction.continueWith(res);
        }
    }

    private void remember(HttpRequestToBeSent req) {
        long now = System.currentTimeMillis();
        if (encryptedPlain.size() > PRUNE_ABOVE) encryptedPlain.values().removeIf(p -> now - p.at() > PENDING_TTL_MS);
        encryptedPlain.put(req.messageId(), new Pending(req, now));
    }

    /** Extract any configured session keys from this response and push them to the server. */
    private void captureSessionKeys(HttpResponseReceived res) {
        if (sessionKeys.isEmpty()) return;
        String url = res.initiatingRequest() != null ? res.initiatingRequest().url() : null;
        List<SessionKeys.Capture> found;
        try {
            found = sessionKeys.extract(url, res.bodyToString(), res::headerValue);
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
