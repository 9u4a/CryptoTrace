package com.cryptotrace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import java.awt.Component;

/** "Decrypted" tabs on request and response editors. Edits are re-encrypted into the original message. */
public final class PlainEditors {
    static final String CAPTION = "Decrypted";

    private PlainEditors() {}

    public static HttpRequestEditorProvider requests(MontoyaApi api, Crypto crypto) {
        return ctx -> new RequestTab(api, crypto, ctx);
    }

    public static HttpResponseEditorProvider responses(MontoyaApi api, Crypto crypto) {
        return ctx -> new ResponseTab(api, crypto, ctx);
    }

    private static RawEditor editor(MontoyaApi api, EditorCreationContext ctx) {
        RawEditor e = ctx.editorMode() == EditorMode.READ_ONLY
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();
        return e;
    }

    private static final class RequestTab implements ExtensionProvidedHttpRequestEditor {
        private final MontoyaApi api;
        private final Crypto crypto;
        private final RawEditor editor;
        private HttpRequestResponse current;
        private Crypto.Result<HttpRequest> decrypted;

        RequestTab(MontoyaApi api, Crypto crypto, EditorCreationContext ctx) {
            this.api = api;
            this.crypto = crypto;
            this.editor = editor(api, ctx);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse rr) {
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
                String note = decrypted.allOk() ? "" : "# CryptoTrace: " + decrypted.errors() + "\n";
                editor.setContents(ByteArray.byteArray(note + decrypted.message().toString()));
            } catch (ServerClient.ServerException e) {
                decrypted = null;
                editor.setContents(ByteArray.byteArray("# CryptoTrace: " + e.getMessage()));
            }
        }

        @Override
        public HttpRequest getRequest() {
            if (!editor.isModified() || decrypted == null) return current.request();
            HttpRequest edited = HttpRequest.httpRequest(current.request().httpService(), stripNote(editor.getContents()));
            try {
                Crypto.Result<HttpRequest> enc = crypto.encryptRequest(edited);
                if (!enc.allOk()) api.logging().logToError("CryptoTrace re-encrypt: " + enc.errors());
                return enc.message();
            } catch (ServerClient.ServerException e) {
                api.logging().logToError("CryptoTrace re-encrypt failed, keeping original: " + e.getMessage());
                return current.request();
            }
        }

        @Override
        public String caption() {
            return CAPTION;
        }

        @Override
        public Component uiComponent() {
            return editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor.isModified();
        }
    }

    private static final class ResponseTab implements ExtensionProvidedHttpResponseEditor {
        private final MontoyaApi api;
        private final Crypto crypto;
        private final RawEditor editor;
        private HttpRequestResponse current;

        ResponseTab(MontoyaApi api, Crypto crypto, EditorCreationContext ctx) {
            this.api = api;
            this.crypto = crypto;
            this.editor = editor(api, ctx);
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse rr) {
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
                String note = dec.allOk() ? "" : "# CryptoTrace: " + dec.errors() + "\n";
                editor.setContents(ByteArray.byteArray(note + dec.message().toString()));
            } catch (ServerClient.ServerException e) {
                editor.setContents(ByteArray.byteArray("# CryptoTrace: " + e.getMessage()));
            }
        }

        @Override
        public HttpResponse getResponse() {
            if (!editor.isModified()) return current.response();
            HttpResponse edited = HttpResponse.httpResponse(stripNote(editor.getContents()));
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
            return editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor.isModified();
        }
    }

    /** Drop our "# CryptoTrace: ..." error banner line if the user left it in. */
    static String stripNote(ByteArray contents) {
        String s = contents.toString();
        return s.startsWith("# CryptoTrace:") ? s.substring(s.indexOf('\n') + 1) : s;
    }
}
