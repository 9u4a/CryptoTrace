package com.cryptotrace;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Suite tab: top bar (start, status, bridge), tabs (configs, bridge, server, options), log. */
public final class SettingsTab {
    private final Settings settings;
    private final ServerClient server;
    private final SessionKeys sessionKeys;
    private final JPanel root = new JPanel(new BorderLayout(8, 8));
    private final JTextField launcher = new JTextField(30);
    private final JTextField script = new JTextField(40);
    private final DefaultListModel<String> configs = new DefaultListModel<>();
    private final JLabel status = new JLabel();
    private final JTextArea log = new JTextArea(14, 80);
    private final JCheckBox bridgeEnabled = new JCheckBox();
    private final JTextField bridgePort = new JTextField(6);
    private final JTextField bridgeToken = new JTextField(34);
    private final JLabel bridgeStatus = new JLabel();
    private Bridge bridge;
    /** Lines appended during a bridge-triggered load, returned to the browser (null otherwise). */
    private volatile List<String> sink;
    private final JCheckBox decryptResponses = new JCheckBox();

    public SettingsTab(Settings settings, ServerClient server, SessionKeys sessionKeys) {
        this(settings, server, sessionKeys, new Scopes());
    }

    public SettingsTab(Settings settings, ServerClient server, SessionKeys sessionKeys, Scopes scopes) {
        this.scopes = scopes;
        this.settings = settings;
        this.server = server;
        this.sessionKeys = sessionKeys;
        // L4 browser oracle: server questions -> broker -> panel (bridge long-poll) -> answers back to the server
        oracle = new OracleBroker((oid, ok, value, error) -> {
            append("oracle #" + oid + (ok ? " answered (" + (value == null ? 0 : value.length()) + " chars)" : " failed: " + error));
            server.oracleResult(oid, ok, value, error);
        });
        oracle.enabled(settings.oracleEnabled());
        oracle.minIntervalMs(settings.oracleIntervalMs());
        server.onExit(this::onServerCrash);
        server.oracleSink(job -> {
            append("oracle #" + job.get("oid").getAsInt() + " asked: " + job.get("fn").getAsString().split("@")[0] + "() " + job.get("dir").getAsString());
            oracle.submit(job);
        });
        build();
    }

    private final OracleBroker oracle;
    private final Scopes scopes;
    private final JCheckBox oracleEnabled = new JCheckBox();
    private final JTextField oracleInterval = new JTextField(5);

    public Component component() {
        return root;
    }

    /**
     * Layout (0.3.0): a fixed top bar (Start / Reload, server status, bridge status, Copy token), tabs for
     * Configs / Browser bridge / Server / Options, and the log always visible below. Explanations live in
     * tooltips. Burp's L&F doesn't render <html> in JLabel, so labels are plain text.
     */
    private void build() {
        root.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        launcher.setText(settings.launcher());
        script.setText(settings.script());
        settings.configs().forEach(configs::addElement);

        JButton start = new JButton("Start / Reload");
        start.setToolTipText("Save the settings, (re)start the local crypto server and load every config (with selftest)");
        start.addActionListener(e -> new Thread(this::startServer, "cryptotrace-start").start());
        JButton stop = new JButton("Stop");
        stop.setToolTipText("Stop the crypto server and forget loaded scopes and captured session keys."
                + " Requests marked plain are blocked until Start / Reload");
        stop.addActionListener(e -> new Thread(this::stopServer, "cryptotrace-stop").start());
        JButton copyTop = new JButton("Copy token");
        copyTop.setToolTipText("Pairing token for the DevTools panel (Burp settings) -- paste it there once");
        copyTop.addActionListener(e -> copyToken());
        JPanel bar = row(start, stop, status, gap(18), new JLabel("Bridge:"), bridgeStatus, copyTop);

        javax.swing.JTabbedPane tabs = new javax.swing.JTabbedPane();
        tabs.addTab("Configs", configsTab());
        tabs.addTab("Browser bridge", pinTop(bridgeTab()));
        tabs.addTab("Server", pinTop(serverTab()));
        tabs.addTab("Options", pinTop(optionsTab()));

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JButton clearLog = new JButton("Clear log");
        clearLog.addActionListener(e -> log.setText(""));
        JPanel logPanel = new JPanel(new BorderLayout());
        JLabel logTitle = new JLabel("Log");
        logTitle.setFont(logTitle.getFont().deriveFont(Font.BOLD));
        logPanel.add(row(logTitle, clearLog), BorderLayout.NORTH);
        logPanel.add(new JScrollPane(log), BorderLayout.CENTER);

        javax.swing.JSplitPane split = new javax.swing.JSplitPane(javax.swing.JSplitPane.VERTICAL_SPLIT, tabs, logPanel);
        split.setResizeWeight(0.45);
        split.setDividerLocation(260);
        root.add(bar, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
        setStatus(false, "stopped");
    }

    private JPanel configsTab() {
        JList<String> list = new JList<>(configs);
        list.setVisibleRowCount(6);
        list.setCellRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> l, Object v, int i, boolean sel, boolean focus) {
                super.getListCellRendererComponent(l, v, i, sel, focus);
                String path = String.valueOf(v);
                java.nio.file.Path f = java.nio.file.Path.of(path);
                boolean received = f.toAbsolutePath().startsWith(receivedDir());
                setText(f.getFileName() + (received ? "    (from browser)" : "    " + f.getParent()));
                setToolTipText(path);
                return this;
            }
        });
        JButton add = new JButton("Add config...");
        add.setToolTipText("Add an exported config.json (Send to Burp adds received ones automatically)");
        add.addActionListener(e -> choose(true).forEach(configs::addElement));
        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> list.getSelectedValuesList().forEach(configs::removeElement));
        JButton open = new JButton("Open received folder");
        open.setToolTipText(receivedDir().toString());
        open.addActionListener(e -> {
            try {
                java.nio.file.Files.createDirectories(receivedDir());
                java.awt.Desktop.getDesktop().open(receivedDir().toFile());
            } catch (Exception ex) {
                append("ERROR cannot open " + receivedDir() + ": " + ex.getMessage());
            }
        });
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        p.add(new JScrollPane(list), BorderLayout.CENTER);
        p.add(row(add, remove, gap(12), open, new JLabel("Changes apply on Start / Reload.")), BorderLayout.SOUTH);
        return p;
    }

    private JPanel bridgeTab() {
        bridgeEnabled.setText("Receive configs from the browser extension");
        bridgeEnabled.setToolTipText("Listens on 127.0.0.1 only; a request needs the token, a local Host and the extension's origin");
        bridgeEnabled.setSelected(settings.bridgeEnabled());
        bridgeEnabled.addActionListener(e -> {
            settings.bridgeEnabled(bridgeEnabled.isSelected());
            restartBridge();
        });
        bridgePort.setText(String.valueOf(settings.bridgePort()));
        JButton applyPort = new JButton("Apply");
        applyPort.addActionListener(e -> {
            try {
                int port = Integer.parseInt(bridgePort.getText().trim());
                if (port < 1 || port > 65535) throw new NumberFormatException();
                settings.bridgePort(port);
                restartBridge();
            } catch (NumberFormatException ex) {
                bridgePort.setText(String.valueOf(settings.bridgePort()));
                append("ERROR bridge port must be 1-65535");
            }
        });
        bridgeToken.setText(settings.bridgeToken());
        bridgeToken.setEditable(false);
        bridgeToken.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> copyToken());
        JButton regen = new JButton("Regenerate");
        regen.setToolTipText("Issue a new token; paste the new one into the browser extension");
        regen.addActionListener(e -> {
            bridgeToken.setText(settings.regenerateBridgeToken());
            append("bridge token regenerated -- paste the new one into the browser extension");
        });
        JPanel p = tabBody();
        p.add(row(bridgeEnabled));
        p.add(row(new JLabel("Port:"), bridgePort, applyPort, muted("Same port in the DevTools panel (default " + Bridge.DEFAULT_PORT + ")")));
        p.add(row(new JLabel("Token:"), bridgeToken, copy, regen));
        p.add(row(muted("Once: DevTools > CryptoTrace > Burp settings > paste token > Save & test. Then Send to Burp.")));
        return p;
    }

    private JPanel serverTab() {
        launcher.setToolTipText("node (or a full path to node.exe), or the packaged crypto-server.exe");
        script.setToolTipText("server/src/main.mjs when launching through node; blank = auto-detect from the jar location; "
                + "leave blank for crypto-server.exe");
        JButton browseScript = new JButton("Browse...");
        browseScript.addActionListener(e -> choose(false).stream().findFirst().ifPresent(script::setText));
        JPanel p = tabBody();
        p.add(row(fixed(new JLabel("Launcher:")), launcher));
        p.add(row(fixed(new JLabel("Server script:")), script, browseScript));
        p.add(row(muted("Saved and applied on Start / Reload.")));
        return p;
    }

    private JPanel optionsTab() {
        decryptResponses.setText("Decrypt responses in Repeater / Intruder / Scanner");
        decryptResponses.setToolTipText("Only for requests CryptoTrace encrypted; never in Proxy");
        decryptResponses.setSelected(settings.decryptResponses());
        decryptResponses.addActionListener(e -> settings.decryptResponses(decryptResponses.isSelected()));
        oracleEnabled.setText("ACTIVE: Browser oracle -- run the page's own function to re-encrypt edited fields");
        oracleEnabled.setToolTipText("For ciphers CryptoTrace can't re-implement (custom code). Runs page JavaScript in the inspected tab"
                + " (no traffic to the target by itself). Needs the DevTools panel open with its oracle switch on. Default off.");
        oracleEnabled.setSelected(settings.oracleEnabled());
        oracleEnabled.addActionListener(e -> {
            settings.oracleEnabled(oracleEnabled.isSelected());
            oracle.enabled(oracleEnabled.isSelected());
            append("browser oracle " + (oracleEnabled.isSelected() ? "ON (runs page code)" : "off"));
        });
        oracleInterval.setText(String.valueOf(settings.oracleIntervalMs()));
        oracleInterval.setToolTipText("Minimum time between two calls into the page (throttle)");
        oracleInterval.addActionListener(e -> applyOracleInterval());
        oracleInterval.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                applyOracleInterval();
            }
        });
        JPanel p = tabBody();
        p.add(row(decryptResponses));
        p.add(row(oracleEnabled));
        p.add(row(new JLabel("    Min interval (ms):"), oracleInterval, muted("one call at a time; Scanner-heavy use is throttled here")));
        p.add(row(muted("Plaintext request: header X-CT-Plain: 1, or right-click > Send to Repeater (Plain). "
                + "A request that fails to encrypt is blocked, never sent in plaintext.")));
        return p;
    }

    private void applyOracleInterval() {
        try {
            int ms = Math.max(0, Integer.parseInt(oracleInterval.getText().trim()));
            settings.oracleIntervalMs(ms);
            oracle.minIntervalMs(ms);
        } catch (NumberFormatException e) {
            oracleInterval.setText(String.valueOf(settings.oracleIntervalMs()));
        }
    }

    private void copyToken() {
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(settings.bridgeToken()), null);
        append("bridge token copied to the clipboard");
    }

    private static JPanel tabBody() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        return p;
    }

    /** Keeps a tab's rows at their natural height at the top. */
    private static JPanel pinTop(JPanel body) {
        JPanel holder = new JPanel(new BorderLayout());
        holder.add(body, BorderLayout.NORTH);
        return holder;
    }

    private static JLabel muted(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(java.awt.Color.GRAY);
        return l;
    }

    private static JLabel fixed(JLabel l) {
        l.setPreferredSize(new java.awt.Dimension(100, l.getPreferredSize().height));
        return l;
    }

    private static Component gap(int w) {
        return Box.createHorizontalStrut(w);
    }

    /** Starts / stops the bridge to match the settings. Call once after construction, and on change. */
    public void restartBridge() {
        if (bridge == null) bridge = new Bridge(settings::bridgeToken, this::receive, this::append, oracle);
        bridge.stop();
        if (!settings.bridgeEnabled()) {
            setBridgeStatus(false, "off");
            return;
        }
        try {
            bridge.start(settings.bridgePort());
            setBridgeStatus(true, "listening on 127.0.0.1:" + bridge.port());
        } catch (java.io.IOException e) {
            append("ERROR bridge: cannot listen on 127.0.0.1:" + settings.bridgePort() + " (" + e.getMessage()
                    + ") -- pick another port and set the same one in the browser extension");
            setBridgeStatus(false, "port " + settings.bridgePort() + " unavailable");
        }
    }

    public void stopBridge() {
        if (bridge != null) bridge.stop();
    }

    /** A config from the browser: confirm custom code, save it, add it to the list, reload the server. */
    private JsonObject receive(JsonObject cfg) throws Exception {
        String name = Bridge.fileNameFor(cfg);
        append("bridge: received config " + name);
        if (Bridge.usesCustomCode(cfg)) {
            boolean[] ok = {false};
            SwingUtilities.invokeAndWait(() -> ok[0] = javax.swing.JOptionPane.showConfirmDialog(root,
                    "The config from the browser (" + name + ") references custom JS modules.\n"
                            + "Custom JS runs in the local server and node:vm is not a security boundary.\n"
                            + "Load it only if you reviewed those modules. Load now?",
                    "CryptoTrace -- custom code", javax.swing.JOptionPane.YES_NO_OPTION,
                    javax.swing.JOptionPane.WARNING_MESSAGE) == javax.swing.JOptionPane.YES_OPTION);
            if (!ok[0]) {
                append("bridge: declined " + name + " (custom code)");
                throw new Bridge.Refused(403, "declined in Burp (config uses custom JS)");
            }
        }
        java.nio.file.Path dir = receivedDir();
        java.nio.file.Files.createDirectories(dir);
        java.nio.file.Path file = dir.resolve(name);
        java.nio.file.Path tmp = dir.resolve(name + ".part");
        java.nio.file.Files.writeString(tmp, ServerClient.GSON.toJson(cfg), java.nio.charset.StandardCharsets.UTF_8);
        java.nio.file.Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        String path = file.toString();
        // Any other received config for the same target (e.g. an older capture saved under the old per-date name)
        // leaves the list: the server would otherwise apply whichever loaded first. The file itself stays.
        String key = Bridge.scopeKey(cfg);
        List<String> replaced = new ArrayList<>();
        for (int i = 0; i < configs.size(); i++) {
            String other = configs.get(i);
            if (other.equals(path) || !java.nio.file.Path.of(other).toAbsolutePath().startsWith(dir.toAbsolutePath())) continue;
            try {
                JsonObject o = com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(java.nio.file.Path.of(other))).getAsJsonObject();
                if (!key.isEmpty() && key.equals(Bridge.scopeKey(o))) replaced.add(other);
            } catch (Exception ignored) { /* unreadable: leave it */ }
        }
        SwingUtilities.invokeAndWait(() -> {
            for (String r : replaced) configs.removeElement(r);
            if (!configs.contains(path)) configs.addElement(path);
        });
        for (String r : replaced) append("bridge: replaced older capture for " + key + ": " + java.nio.file.Path.of(r).getFileName());
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        sink = lines;
        boolean ok;
        try {
            // A running server only reloads its configs: restarting would fail in-flight Intruder/Scanner calls
            // and drop session keys captured since the last start.
            ok = server.isRunning() ? reloadConfigs() : startServer();
        } finally {
            sink = null;
        }
        JsonObject o = new JsonObject();
        o.addProperty("ok", ok);
        o.addProperty("file", path);
        o.addProperty("status", lastStatus);
        com.google.gson.JsonArray arr = new com.google.gson.JsonArray();
        synchronized (lines) {
            for (String l : lines) arr.add(l);
        }
        o.add("log", arr);
        return o;
    }

    /** Received configs live outside any repo: ~/.cryptotrace/received (they hold target keys). */
    static java.nio.file.Path receivedDir() {
        return java.nio.file.Path.of(System.getProperty("user.home"), ".cryptotrace", "received");
    }

    private void setBridgeStatus(boolean ok, String text) {
        SwingUtilities.invokeLater(() -> {
            bridgeStatus.setText((ok ? "[ON] " : "[OFF] ") + text);
            bridgeStatus.setForeground(ok ? new java.awt.Color(0x18, 0x80, 0x38) : java.awt.Color.GRAY);
        });
    }

    private static JPanel row(Component... cs) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (Component c : cs) p.add(c);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private List<String> choose(boolean json) {
        JFileChooser fc = new JFileChooser();
        fc.setMultiSelectionEnabled(json);
        if (json) fc.setFileFilter(new FileNameExtensionFilter("CryptoTrace config (*.json)", "json"));
        if (fc.showOpenDialog(root) != JFileChooser.APPROVE_OPTION) return List.of();
        List<String> out = new ArrayList<>();
        if (json) for (var f : fc.getSelectedFiles()) out.add(f.getAbsolutePath());
        else out.add(fc.getSelectedFile().getAbsolutePath());
        return out;
    }

    /** The config list minus files that no longer exist (moved / deleted): those are dropped with a warning
     *  instead of failing the whole load. */
    private List<String> presentConfigs() {
        List<String> files = new ArrayList<>(Collections.list(configs.elements()));
        List<String> missing = missingConfigs(files);
        if (!missing.isEmpty()) {
            files.removeAll(missing);
            for (String m : missing) append("WARN config not found, removed from the list: " + m);
            SwingUtilities.invokeLater(() -> missing.forEach(configs::removeElement));
        }
        return files;
    }

    /** Load the config list into the running server without restarting it (session keys are kept). */
    public synchronized boolean reloadConfigs() {
        List<String> files = presentConfigs();
        settings.configs(files);
        try {
            append("reloading " + files.size() + " config(s) into the running server");
            return loadAndReport(files, false);
        } catch (Exception e) {
            append("ERROR " + e.getMessage());
            setStatus(false, "reload failed: " + e.getMessage());
            return false;
        }
    }

    /** Persist the form, (re)start the server process and load configs. Runs off the EDT. */
    private boolean shutDown;

    /** Extension unload: waits for a start in progress (both synchronized), so no server process is left running. */
    public synchronized void shutdown() {
        shutDown = true;
        server.close();
    }

    /** Bumped by Stop: a crash-restart scheduled before it must not bring the server back. */
    private volatile long stopEpoch;

    /** User Stop: no auto-restart (close() is not a crash), Decrypted tabs go away, captured keys are dropped. */
    public synchronized void stopServer() {
        stopEpoch++;
        boolean wasRunning = server.isRunning();
        server.close();
        scopes.set(null);
        sessionKeys.clear();
        append(wasRunning ? "stopped by user - scopes and session keys cleared" : "stop: server was not running - scopes and session keys cleared");
        setStatus(false, "stopped");
    }

    public synchronized boolean startServer() {
        if (shutDown) return false;
        List<String> files = presentConfigs();
        String l = Settings.unquote(launcher.getText());
        String s = Settings.unquote(script.getText());
        if (l.toLowerCase().matches(".*\\.(mjs|js)$")) { // script pasted into the launcher field
            if (s.isEmpty()) s = l;
            l = "node";
        }
        settings.launcher(l);
        settings.script(s);
        String shownLauncher = settings.launcher();
        String shownScript = settings.script();
        SwingUtilities.invokeLater(() -> {
            launcher.setText(shownLauncher);
            script.setText(shownScript);
        });
        settings.configs(files);
        String problem = preflight(settings.launcher(), settings.script(), settings.configs());
        if (problem != null) {
            append("ERROR " + problem);
            setStatus(false, "not started: " + problem);
            return false;
        }
        try {
            append("starting: " + String.join(" ", ServerClient.command(settings.launcher(), settings.script())));
            server.start(ServerClient.command(settings.launcher(), settings.script()));
            JsonObject health = server.call("health", null);
            String serverVersion = health.get("version").getAsString();
            append("server " + serverVersion + " started");
            String jarVersion = SettingsTab.class.getPackage().getImplementationVersion();
            if (jarVersion != null && !jarVersion.equals(serverVersion)) {
                append("WARN server " + serverVersion + " != extension " + jarVersion
                        + " - use the server script/exe from the same release");
            }
            return loadAndReport(files, true);
        } catch (Exception e) {
            append("ERROR " + e.getMessage());
            setStatus(false, "not running: " + e.getMessage());
            return false;
        }
    }

    /** Load files and log the result. Session keys captured so far survive: a reloaded server kept them itself,
     *  a restarted one (freshStart) gets them pushed again, so the logged-in session keeps working. */
    private boolean loadAndReport(List<String> files, boolean freshStart) throws ServerClient.ServerException {
        List<SessionKeys.Capture> known = sessionKeys.pushed();
        JsonObject loaded = server.load(files);
        sessionKeys.setRules(loaded);
        scopes.set(loaded);
        if (!sessionKeys.isEmpty()) append("watching responses for " + sessionKeys.size() + " session key(s)");
        int restored = 0;
        for (SessionKeys.Capture c : known) {
            if (freshStart) {
                JsonObject args = new JsonObject();
                args.addProperty("profile", c.profile());
                args.addProperty("keyName", c.keyName());
                args.addProperty("value", c.value());
                try {
                    server.call("key", args);
                } catch (ServerClient.ServerException e) {
                    continue; // that profile/key is gone from the configs
                }
                restored++;
            }
            sessionKeys.markPushed(c);
        }
        if (restored > 0) append("restored " + restored + " captured session key(s) into the new server");
        int bad = 0;
        for (JsonElement r : loaded.getAsJsonArray("results")) {
            JsonObject o = r.getAsJsonObject();
            if (o.has("error")) {
                bad++;
                append("ERROR " + o.get("file").getAsString() + ": " + o.get("error").getAsString());
                continue;
            }
            StringBuilder sb = new StringBuilder("loaded " + o.get("profile").getAsString() + " - selftest:");
            if (o.getAsJsonArray("selftest").isEmpty()) sb.append(" (no vectors)");
            for (JsonElement t : o.getAsJsonArray("selftest")) {
                JsonObject tt = t.getAsJsonObject();
                boolean ok = tt.get("ok").getAsBoolean();
                if (!ok) bad++;
                sb.append(' ').append(tt.get("cipher").getAsString()).append('=')
                        .append(ok ? "OK" : "FAIL(" + tt.get("error").getAsString() + ")");
            }
            append(sb.toString());
            if (o.has("sessionKeysKept")) append("  kept " + o.get("sessionKeysKept").getAsInt() + " captured session key(s)");
            if (o.has("scope") && !o.get("scope").isJsonNull()) {
                StringBuilder sc = new StringBuilder("  scope:");
                for (JsonElement se : o.getAsJsonArray("scope")) {
                    JsonObject so = se.getAsJsonObject();
                    sc.append(' ').append(so.get("host").getAsString());
                    if (so.has("port") && !so.get("port").isJsonNull()) sc.append(':').append(so.get("port").getAsString());
                    String pr = so.get("pathRegex").getAsString();
                    if (!".*".equals(pr)) sc.append(" path=").append(pr);
                }
                append(sc.toString());
            }
            if (o.has("warnings") && !o.get("warnings").isJsonNull()) {
                for (JsonElement w : o.getAsJsonArray("warnings")) append("  WARN " + w.getAsString());
            }
            // ciphers the server identified from a traced page function's candidates (0.5.0)
            if (o.has("identified") && o.get("identified").isJsonArray()) {
                for (JsonElement ie : o.getAsJsonArray("identified")) {
                    JsonObject id = ie.getAsJsonObject();
                    StringBuilder line = new StringBuilder("  IDENTIFIED ").append(id.get("cipher").getAsString())
                            .append(" = ").append(id.get("alg").getAsString()).append(" key=").append(id.get("key").getAsString());
                    if (id.has("iv") && id.get("iv").isJsonObject()) {
                        JsonObject iv = id.getAsJsonObject("iv");
                        line.append(" iv=").append(iv.has("from") ? "from-" + iv.get("from").getAsString()
                                : iv.get("encoding").getAsString() + ":" + iv.get("value").getAsString());
                    }
                    line.append(" padding=").append(id.get("padding").getAsString());
                    append(line.toString());
                }
            }
        }
        setStatus(bad == 0, bad == 0 ? "running - " + files.size() + " config(s)" : "running with " + bad + " problem(s) - see log");
        return bad == 0;
    }

    static List<String> missingConfigs(List<String> files) {
        List<String> out = new ArrayList<>();
        for (String f : files) {
            if (!java.nio.file.Files.isRegularFile(java.nio.file.Path.of(f))) out.add(f);
        }
        return out;
    }

    /** Returns a human-readable problem, or null if the launch looks sane. */
    static String preflight(String launcher, String script, List<String> configs) {
        String exe = java.nio.file.Path.of(launcher).getFileName().toString().toLowerCase();
        boolean isNode = exe.equals("node") || exe.equals("node.exe");
        if (isNode && script.isEmpty()) return "Server script is empty - set it to <repo>\\server\\src\\main.mjs";
        if (!script.isEmpty() && !java.nio.file.Files.isRegularFile(java.nio.file.Path.of(script))) {
            return "Server script not found: " + script;
        }
        for (String c : configs) {
            if (!java.nio.file.Files.isRegularFile(java.nio.file.Path.of(c))) return "Config not found: " + c;
        }
        return null;
    }

    private static final int MAX_LOG_LINES = 5000;

    // Blocked requests (never sent in plaintext): shown in the log, a reason repeated within 10 s folded into a count.
    private String lastBlocked = "";
    private long lastBlockedAt;
    private int blockedRepeats;
    private int blockedTotal;

    public synchronized void blocked(String why) {
        blockedTotal++;
        long now = System.currentTimeMillis();
        if (why.equals(lastBlocked) && now - lastBlockedAt < 10_000) {
            blockedRepeats++;
            return;
        }
        if (blockedRepeats > 0) append("BLOCKED x" + blockedRepeats + " more (same reason)");
        lastBlocked = why;
        lastBlockedAt = now;
        blockedRepeats = 0;
        append("BLOCKED (not sent, total " + blockedTotal + "): " + why);
    }

    /** Keep the log area bounded over a long session (drop the oldest lines). EDT only. */
    private void trimLog() {
        int extra = log.getLineCount() - MAX_LOG_LINES;
        if (extra <= 0) return;
        try {
            log.getDocument().remove(0, log.getLineEndOffset(extra - 1));
        } catch (javax.swing.text.BadLocationException ignored) {
            // concurrent change: trimmed next time
        }
    }

    public void append(String line) {
        List<String> s = sink;
        if (s != null) s.add(line);
        String ts = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            log.append("[" + ts + "] " + line + "\n");
            trimLog();
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private volatile String lastStatus = "";
    static final int STATUS_MAX = 60;

    private void setStatus(boolean ok, String text) {
        lastStatus = text;
        boolean down = !ok && text.startsWith("DOWN");
        String full = (ok ? "[ON] " : down ? "[DOWN] " : "[OFF] ") + (down ? text.substring(4).replaceFirst("^[\\s-]+", "") : text);
        SwingUtilities.invokeLater(() -> {
            // the top bar is a one-row FlowLayout: a label wider than the bar wraps to a hidden second row,
            // so keep it short and put the whole text in the tooltip
            status.setText(full.length() > STATUS_MAX ? full.substring(0, STATUS_MAX - 3) + "..." : full);
            status.setToolTipText(full);
            status.setForeground(ok ? new java.awt.Color(0x18, 0x80, 0x38) : down ? new java.awt.Color(0xc0, 0x20, 0x20) : java.awt.Color.GRAY);
        });
    }

    // Crash recovery: restart after 1 s, 2 s, 4 s; more than 3 crashes in 5 minutes means something is wrong
    // with the config or launcher, so stop and leave it to the user (Start / Reload).
    private static final int MAX_RESTARTS = 3;
    private static final long RESTART_WINDOW_MS = 5 * 60_000L;
    private final java.util.Deque<Long> restarts = new java.util.ArrayDeque<>();

    private void onServerCrash(String reason) {
        append("ERROR " + reason);
        long now = System.currentTimeMillis();
        int n;
        synchronized (restarts) {
            while (!restarts.isEmpty() && now - restarts.peekFirst() > RESTART_WINDOW_MS) restarts.pollFirst();
            n = restarts.size();
            if (n < MAX_RESTARTS) restarts.addLast(now);
        }
        if (n >= MAX_RESTARTS) {
            setStatus(false, "DOWN - crashed " + MAX_RESTARTS + " times in 5 min; fix the cause, then Start / Reload. " + reason);
            return;
        }
        long delay = 1000L << n;
        setStatus(false, "DOWN - restarting in " + delay / 1000 + " s. " + reason);
        long epoch = stopEpoch;
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                return;
            }
            if (server.isRunning()) return; // the user restarted it meanwhile
            if (stopEpoch != epoch) return; // the user pressed Stop meanwhile
            append("auto-restart " + (n + 1) + "/" + MAX_RESTARTS + " after a crash");
            startServer();
        }, "cryptotrace-restart");
        t.setDaemon(true);
        t.start();
    }
}
