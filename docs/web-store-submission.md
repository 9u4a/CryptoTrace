# Chrome Web Store submission checklist

Submission itself must be done by the developer (personal account, **confirm with employer before
publishing** — design R15). This file has the package steps and ready-to-paste field content so the
actual submission is copy/paste. Nothing here is sent anywhere by the tool.

## 0. Before you start
- [ ] Employer/manager sign-off to publish `9u4a/CryptoTrace` publicly as a personal-account extension.
- [ ] A Chrome Web Store developer account (one-time US$5 registration).
- [ ] Repo is public and the pushed commit matches the version you package.

## 1. Build the package
```
node scripts/pack-chrome.mjs
```
Produces `output/cryptotrace-chrome-<version>.zip` (gitignored). Upload **this zip** as the package.
It contains only runtime files (no tests): manifest, html/js, icons.

## 2. Store listing (copy/paste)
- **Name:** CryptoTrace
- **Summary (≤132 chars):** Trace client-side crypto calls while debugging, and export an algorithm/key/location config for the CryptoTrace Burp extension.
- **Category:** Developer Tools
- **Language:** English (add Korean later if wanted)
- **Description:**
  > CryptoTrace records the cryptographic API calls a web page makes (WebCrypto, CryptoJS, JSEncrypt,
  > including bundled copies and Web Workers) while you debug it, and exports an algorithm/key/apply-
  > location config. The companion Burp Suite extension uses that config to view, edit, and scan
  > otherwise-encrypted requests and responses as plaintext.
  >
  > All processing is local — nothing is sent to any server. Intended for authorized security testing
  > only.

## 3. Graphics
- [ ] Store icon 128×128 — already in `chrome-ext/icons/icon128.png`.
- [ ] At least one screenshot, 1280×800 or 640×400 (PNG/JPEG). Suggested shots:
  - DevTools **CryptoTrace** panel with a few captured rows (algorithm/key/location columns).
  - The exported `config.json` preview.
  - Burp **Decrypted** editor tab showing plaintext of an encrypted request.
  - Use the sample target (`node samples/server.mjs` → http://127.0.0.1:8088), **never a real target**, so no client data appears.
- [ ] (Optional) small promo tile 440×280.

## 4. Privacy tab
- **Single purpose:** Record a page's client-side cryptographic calls during debugging and export a
  configuration for the CryptoTrace Burp extension.
- **Permission justifications:**
  - `debugger` — inject the crypto hooks before page scripts run (including Web Workers and iframes) and open call sites in DevTools. No remote debugging.
  - `storage` — persist the extension's own settings only.
  - Host permissions: none requested.
- **Data usage:** check **does not collect or use** user data. No analytics/telemetry; all processing local.
- **Privacy policy URL:** https://github.com/9u4a/CryptoTrace/blob/main/PRIVACY.md

## 5. Submit
- [ ] Upload zip, fill the fields above, add screenshots, set visibility (Public or Unlisted).
- [ ] Submit for review. **Do not resubmit repeatedly** (design R15) — wait out the review.
- [ ] On a later version bump: re-run step 1 and upload the new zip; keep the listing text in sync.

## Notes
- The extension declares no `host_permissions` and no broad content scripts, which keeps review simple.
- Keep the store description in sync with `README.md` and the manifest `description`.
