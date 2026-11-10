package com.cryptotrace;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

/** Entry point. Wires the local crypto server into Burp's editors, HTTP pipeline, Scanner and context menu. */
public final class CryptoTraceExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("CryptoTrace");
        Settings settings = new Settings(api.persistence().preferences(), api.extension().filename());

        final SettingsTab[] tab = new SettingsTab[1];
        ServerClient server = new ServerClient(line -> {
            api.logging().logToOutput(line);
            if (tab[0] != null) tab[0].append(line);
        }, 5000);
        Crypto crypto = new Crypto(server);
        SessionKeys sessionKeys = new SessionKeys();
        tab[0] = new SettingsTab(settings, server, sessionKeys);

        api.userInterface().registerSuiteTab("CryptoTrace", tab[0].component());
        api.userInterface().registerHttpRequestEditorProvider(PlainEditors.requests(api, crypto));
        api.userInterface().registerHttpResponseEditorProvider(PlainEditors.responses(api, crypto));
        api.userInterface().registerContextMenuItemsProvider(new PlainContextMenu(api, crypto));
        api.http().registerHttpHandler(new CryptoHttpHandler(api, crypto, settings, server, sessionKeys));
        api.scanner().registerInsertionPointProvider(new PlainInsertionPoints(api, crypto));
        api.extension().registerUnloadingHandler(server::close);

        // Auto-start when a launcher and configs were saved previously.
        if (!settings.configs().isEmpty()) new Thread(tab[0]::startServer, "cryptotrace-autostart").start();
        api.logging().logToOutput("CryptoTrace loaded. Configure the server in the CryptoTrace tab.");
    }
}
