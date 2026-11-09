package com.cryptotrace;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

/** Right-click "Send to Repeater (Plain)": decrypt, add X-CT-Plain, open in Repeater. */
public final class PlainContextMenu implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final Crypto crypto;

    public PlainContextMenu(MontoyaApi api, Crypto crypto) {
        this.api = api;
        this.crypto = crypto;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequest> requests = new ArrayList<>();
        event.messageEditorRequestResponse().ifPresent(m -> requests.add(m.requestResponse().request()));
        for (HttpRequestResponse rr : event.selectedRequestResponses()) requests.add(rr.request());
        if (requests.isEmpty()) return List.of();

        JMenuItem item = new JMenuItem("Send to Repeater (Plain)");
        item.addActionListener(e -> new Thread(() -> send(requests), "cryptotrace-send").start());
        return List.of(item);
    }

    private void send(List<HttpRequest> requests) {
        for (HttpRequest req : requests) {
            try {
                Crypto.Result<HttpRequest> dec = crypto.decryptRequest(req);
                if (dec.matched() == null) {
                    api.logging().logToError("CryptoTrace: no profile matches " + req.url());
                    continue;
                }
                if (!dec.allOk()) api.logging().logToError("CryptoTrace partial decrypt: " + dec.errors());
                HttpRequest plain = dec.message().withAddedHeader(Crypto.PLAIN_MARKER, "1");
                api.repeater().sendToRepeater(plain, "CT " + dec.matched());
            } catch (ServerClient.ServerException ex) {
                api.logging().logToError("CryptoTrace: " + ex.getMessage());
            }
        }
    }
}
