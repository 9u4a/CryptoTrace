# Privacy Policy — CryptoTrace

CryptoTrace does not collect, transmit, sell, or share any user data.

- **All processing is local.** The Chrome extension records cryptographic API calls on pages where the
  user explicitly enables hooking, and shows them only in the local DevTools panel.
- **No remote servers.** The extension, the local crypto server, and the Burp Suite extension talk to
  each other only on the user's own machine (process stdio or `127.0.0.1`). Nothing is sent to the
  developer or any third party. There is no analytics or telemetry.
- **Exports stay with the user.** Exported configuration files (which may contain keys captured from the
  inspected page) are saved only where the user chooses.
- **Send to Burp.** When the user clicks Send to Burp (or turns on auto-send), the extension posts the
  configuration to the CryptoTrace Burp extension at `http://127.0.0.1:<port>` on the same machine, with a
  pairing token the user copied from Burp. Burp saves it under `~/.cryptotrace/received/`. Nothing leaves
  the machine.
- **Storage.** The extension uses `chrome.storage` only for its own settings (Burp port, pairing token,
  auto-send).
- **Permissions.** `debugger` is used to inject hooks before page scripts run (including Web Workers and
  iframes) and to open call sites in DevTools; `storage` holds settings; the `http://127.0.0.1/*` host
  permission lets Send to Burp reach the local Burp extension (loopback only).

Intended for authorized security testing only.

Contact: open an issue at https://github.com/9u4a/CryptoTrace/issues
