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

/** Suite tab: server launcher, config files, start/reload, status + log. */
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
    private final JCheckBox bridgeEnabled = new JCheckBox("Receive configs from the browser extension (127.0.0.1 only)");
    private final JTextField bridgePort = new JTextField(6);
    private final JTextField bridgeToken = new JTextField(34);
    private final JLabel bridgeStatus = new JLabel();
    private Bridge bridge;
    /** Lines appended during a bridge-triggered load, returned to the browser (null otherwise). */
    private volatile List<String> sink;
    private final JCheckBox decryptResponses = new JCheckBox("Decrypt responses of requests CryptoTrace encrypted (Repeater/Intruder/Scanner; never Proxy)");

    public SettingsTab(Settings settings, ServerClient server, SessionKeys sessionKeys) {
        this.settings = settings;
        this.server = server;
        this.sessionKeys = sessionKeys;
        build();
    }

    public Component component() {
        return root;
    }

    private void build() {
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));

        launcher.setText(settings.launcher());
        script.setText(settings.script());
        settings.configs().forEach(configs::addElement);
        decryptResponses.setSelected(settings.decryptResponses());
        decryptResponses.addActionListener(e -> settings.decryptResponses(decryptResponses.isSelected()));

        form.add(row(new JLabel("Launcher (node or crypto-server.exe):"), launcher));
        JButton browseScript = new JButton("Browse...");
        browseScript.addActionListener(e -> choose(false).stream().findFirst().ifPresent(script::setText));
        form.add(row(new JLabel("Server script (blank = auto-detect from jar location):"), script, browseScript));

        JList<String> list = new JList<>(configs);
        list.setVisibleRowCount(5);
        JButton add = new JButton("Add config...");
        add.addActionListener(e -> choose(true).forEach(configs::addElement));
        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> list.getSelectedValuesList().forEach(configs::removeElement));
        JPanel cfg = new JPanel(new BorderLayout(4, 4));
        cfg.setBorder(BorderFactory.createTitledBorder("Config files (exported profiles)"));
        cfg.add(new JScrollPane(list), BorderLayout.CENTER);
        cfg.add(row(add, remove), BorderLayout.SOUTH);
        form.add(cfg);

        JButton start = new JButton("Start / Reload");
        start.addActionListener(e -> new Thread(this::startServer, "cryptotrace-start").start());
        form.add(row(start, status));
        form.add(bridgePanel());
        form.add(row(decryptResponses));
        form.add(Box.createVerticalStrut(6));
        // Burp's L&F doesn't render <html> in JLabel (the tags show as text), so plain lines only.
        form.add(row(new JLabel("Plaintext requests: add the header X-CT-Plain: 1, or right-click > Send to Repeater (Plain).")));
        form.add(row(new JLabel("If encryption fails the request is blocked, never sent in plaintext.")));

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        root.add(form, BorderLayout.NORTH);
        root.add(new JScrollPane(log), BorderLayout.CENTER);
        setStatus(false, "stopped");
    }

    // ---- browser bridge (0.3.0) -------------------------------------------------------------

    private JPanel bridgePanel() {
        bridgeEnabled.setSelected(settings.bridgeEnabled());
        bridgePort.setText(String.valueOf(settings.bridgePort()));
        bridgeToken.setText(settings.bridgeToken());
        bridgeToken.setEditable(false);
        bridgeToken.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        bridgeEnabled.addActionListener(e -> {
            settings.bridgeEnabled(bridgeEnabled.isSelected());
            restartBridge();
        });
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
        JButton copy = new JButton("Copy token");
        copy.addActionListener(e -> java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new java.awt.datatransfer.StringSelection(settings.bridgeToken()), null));
        JButton regen = new JButton("Regenerate");
        regen.setToolTipText("Issue a new token; the browser extension must be given the new one");
        regen.addActionListener(e -> {
            bridgeToken.setText(settings.regenerateBridgeToken());
            append("bridge token regenerated -- paste the new one into the browser extension");
        });
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createTitledBorder("Browser bridge (Send to Burp)"));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.add(row(bridgeEnabled, new JLabel("Port:"), bridgePort, applyPort, bridgeStatus));
        p.add(row(new JLabel("Token:"), bridgeToken, copy, regen));
        p.add(row(new JLabel("Paste the token once into the CryptoTrace DevTools panel (Burp settings), then use Send to Burp.")));
        return p;
    }

    /** Starts / stops the bridge to match the settings. Call once after construction, and on change. */
    public void restartBridge() {
        if (bridge == null) bridge = new Bridge(settings::bridgeToken, this::receive, this::append);
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
        SwingUtilities.invokeAndWait(() -> {
            if (!configs.contains(path)) configs.addElement(path);
        });
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        sink = lines;
        boolean ok;
        try {
            ok = startServer();
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

    /** Persist the form, (re)start the server process and load configs. Runs off the EDT. */
    public synchronized boolean startServer() {
        List<String> files = new ArrayList<>(Collections.list(configs.elements()));
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
            append("server " + health.get("version").getAsString() + " started");
            JsonObject loaded = server.load(files);
            sessionKeys.setRules(loaded);
            if (!sessionKeys.isEmpty()) append("watching responses for " + sessionKeys.size() + " session key(s)");
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
            }
            setStatus(bad == 0, bad == 0 ? "running - " + files.size() + " config(s)" : "running with " + bad + " problem(s) - see log");
            return bad == 0;
        } catch (Exception e) {
            append("ERROR " + e.getMessage());
            setStatus(false, "not running: " + e.getMessage());
            return false;
        }
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

    public void append(String line) {
        List<String> s = sink;
        if (s != null) s.add(line);
        String ts = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            log.append("[" + ts + "] " + line + "\n");
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private volatile String lastStatus = "";

    private void setStatus(boolean ok, String text) {
        lastStatus = text;
        SwingUtilities.invokeLater(() -> {
            status.setText((ok ? "[ON] " : "[OFF] ") + text);
            status.setForeground(ok ? new java.awt.Color(0x18, 0x80, 0x38) : java.awt.Color.GRAY);
        });
    }
}
