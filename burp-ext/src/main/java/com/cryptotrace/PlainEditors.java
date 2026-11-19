package com.cryptotrace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import java.awt.Component;

/**
 * "Decrypted" tabs on request and response editors. Edits are re-encrypted into the original message.
 * Each tab embeds Burp's own HTTP editor, so the plaintext gets Burp's Pretty / Raw / Hex views and JSON
 * highlighting. Errors are shown as an {@link #ERROR_HEADER} header (stripped again before re-encrypting).
 */
public final class PlainEditors {
    static final String CAPTION = "Decrypted";
    static final String ERROR_HEADER = "X-CryptoTrace-Error";

    private PlainEditors() {}

    public static HttpRequestEditorProvider requests(MontoyaApi api, Crypto crypto) {
        return ctx -> new RequestTab(api, crypto, ctx);
    }

    public static HttpResponseEditorProvider responses(MontoyaApi api, Crypto crypto) {
        return ctx -> new ResponseTab(api, crypto, ctx);
    }

    /** True while we build the nested Burp editor, so the tabs Burp adds to it know they are nested. */
    private static final ThreadLocal<Boolean> BUILDING = ThreadLocal.withInitial(() -> false);

    /** Our tab inside our own embedded editor (or any extension-made editor) would show "Decrypted" twice. */
    private static boolean nested(EditorCreationContext ctx) {
        return BUILDING.get() || (ctx.toolSource() != null && ctx.toolSource().isFromTool(ToolType.EXTENSIONS));
    }

    private static <T> T building(java.util.function.Supplier<T> make) {
        BUILDING.set(true);
        try {
            return make.get();
        } finally {
            BUILDING.set(false);
        }
    }

    private static EditorOptions[] options(EditorCreationContext ctx) {
        return ctx.editorMode() == EditorMode.READ_ONLY ? new EditorOptions[] {EditorOptions.READ_ONLY} : new EditorOptions[0];
    }

    private static final class RequestTab implements ExtensionProvidedHttpRequestEditor {
        private final MontoyaApi api;
        private final Crypto crypto;
        private final boolean nested;
        private final HttpRequestEditor editor;
        private HttpRequestResponse current;
        private Crypto.Result<HttpRequest> decrypted;

        RequestTab(MontoyaApi api, Crypto crypto, EditorCreationContext ctx) {
            this.api = api;
            this.crypto = crypto;
            this.nested = nested(ctx);
            this.editor = nested ? null : building(() -> api.userInterface().createHttpRequestEditor(options(ctx)));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse rr) {
            if (nested) return false;
            try {
                return rr.request() != null && crypto.decryptRequest(rr.request()).matched() != null;
            } catch (ServerClient.ServerException e) {
                return false;
            }
        }

        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            current = rr;
            try {
                decrypted = crypto.decryptRequest(rr.request());
                HttpRequest shown = decrypted.message();
                editor.setRequest(decrypted.allOk() ? shown : shown.withAddedHeader(ERROR_HEADER, oneLine(decrypted.errors())));
            } catch (ServerClient.ServerException e) {
                decrypted = null;
                editor.setRequest(rr.request().withAddedHeader(ERROR_HEADER, oneLine(e.getMessage())));
            }
        }

        @Override
        public HttpRequest getRequest() {
            if (!editor.isModified() || decrypted == null) return current.request();
            // Apply the edited path/headers/body onto the ORIGINAL request object so its HTTP/2
            // metadata, header order and casing survive (parsing raw text would discard them).
            HttpRequest edited = mergeOnto(current.request(), editor.getRequest().withRemovedHeader(ERROR_HEADER));
            try {
                Crypto.Result<HttpRequest> enc = crypto.encryptRequest(edited);
                if (!enc.allOk()) api.logging().logToError("CryptoTrace re-encrypt: " + enc.errors());
                return enc.message();
            } catch (ServerClient.ServerException e) {
                api.logging().logToError("CryptoTrace re-encrypt failed, keeping original: " + e.getMessage());
                return current.request();
            }
        }

        /** Read the edited request's fields only, then transplant them onto `base`. */
        private static HttpRequest mergeOnto(HttpRequest base, HttpRequest parsed) {
            HttpRequest merged = parsed.path().equals(base.path()) ? base : base.withPath(parsed.path());
            java.util.Set<String> want = new java.util.HashSet<>();
            for (HttpHeader h : parsed.headers()) want.add(h.name().toLowerCase());
            for (HttpHeader h : base.headers()) if (!want.contains(h.name().toLowerCase())) merged = merged.withRemovedHeader(h.name());
            for (HttpHeader h : parsed.headers()) {
                String old = merged.headerValue(h.name());
                if (old == null) merged = merged.withAddedHeader(h.name(), h.value());
                else if (!old.equals(h.value())) merged = merged.withUpdatedHeader(h.name(), h.value());
            }
            return merged.withBody(parsed.body());
        }

        @Override
        public String caption() {
            return CAPTION;
        }

        @Override
        public Component uiComponent() {
            return editor == null ? new javax.swing.JPanel() : editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor == null ? null : editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor != null && editor.isModified();
        }
    }

    private static final class ResponseTab implements ExtensionProvidedHttpResponseEditor {
        private final MontoyaApi api;
        private final Crypto crypto;
        private final boolean nested;
        private final HttpResponseEditor editor;
        private HttpRequestResponse current;

        ResponseTab(MontoyaApi api, Crypto crypto, EditorCreationContext ctx) {
            this.api = api;
            this.crypto = crypto;
            this.nested = nested(ctx);
            this.editor = nested ? null : building(() -> api.userInterface().createHttpResponseEditor(options(ctx)));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse rr) {
            if (nested) return false;
            if (rr.request() == null || rr.response() == null) return false;
            // Already decrypted in flight by CryptoHttpHandler: the normal Response tab shows plaintext.
            if (rr.response().hasHeader(CryptoHttpHandler.DECRYPTED_MARKER)) return false;
            try {
                return crypto.decryptResponse(rr.request(), rr.response()).matched() != null;
            } catch (ServerClient.ServerException e) {
                return false;
            }
        }

        @Override
        public void setRequestResponse(HttpRequestResponse rr) {
            current = rr;
            try {
                Crypto.Result<HttpResponse> dec = crypto.decryptResponse(rr.request(), rr.response());
                HttpResponse shown = dec.message();
                editor.setResponse(dec.allOk() ? shown : shown.withAddedHeader(ERROR_HEADER, oneLine(dec.errors())));
            } catch (ServerClient.ServerException e) {
                editor.setResponse(rr.response().withAddedHeader(ERROR_HEADER, oneLine(e.getMessage())));
            }
        }

        @Override
        public HttpResponse getResponse() {
            if (!editor.isModified()) return current.response();
            HttpResponse edited = editor.getResponse().withRemovedHeader(ERROR_HEADER);
            try {
                return crypto.encryptResponse(current.request(), edited).message();
            } catch (ServerClient.ServerException e) {
                api.logging().logToError("CryptoTrace re-encrypt failed, keeping original: " + e.getMessage());
                return current.response();
            }
        }

        @Override
        public String caption() {
            return CAPTION;
        }

        @Override
        public Component uiComponent() {
            return editor == null ? new javax.swing.JPanel() : editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor == null ? null : editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor != null && editor.isModified();
        }
    }

    /** Header values must stay on one line. */
    static String oneLine(String s) {
        return s == null ? "" : s.replaceAll("[\\r\\n]+", " ").trim();
    }
}
