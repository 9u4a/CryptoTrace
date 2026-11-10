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
        JButton browseScript = new JButton("Browse…");
        browseScript.addActionListener(e -> choose(false).stream().findFirst().ifPresent(script::setText));
        form.add(row(new JLabel("Server script (blank = auto-detect from jar location):"), script, browseScript));

        JList<String> list = new JList<>(configs);
        list.setVisibleRowCount(5);
        JButton add = new JButton("Add config…");
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
        form.add(row(decryptResponses));
        form.add(Box.createVerticalStrut(6));
        form.add(row(new JLabel("<html>Plaintext requests: add header <b>X-CT-Plain: 1</b> (or right-click → <b>Send to Repeater (Plain)</b>). "
                + "If encryption fails the request is blocked, never sent in plaintext.</html>")));

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        root.add(form, BorderLayout.NORTH);
        root.add(new JScrollPane(log), BorderLayout.CENTER);
        setStatus(false, "stopped");
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
    public void startServer() {
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
            return;
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
                StringBuilder sb = new StringBuilder("loaded " + o.get("profile").getAsString() + " — selftest:");
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
            setStatus(bad == 0, bad == 0 ? "running — " + files.size() + " config(s)" : "running with " + bad + " problem(s) — see log");
        } catch (Exception e) {
            append("ERROR " + e.getMessage());
            setStatus(false, "not running: " + e.getMessage());
        }
    }

    /** Returns a human-readable problem, or null if the launch looks sane. */
    static String preflight(String launcher, String script, List<String> configs) {
        String exe = java.nio.file.Path.of(launcher).getFileName().toString().toLowerCase();
        boolean isNode = exe.equals("node") || exe.equals("node.exe");
        if (isNode && script.isEmpty()) return "Server script is empty — set it to <repo>\\server\\src\\main.mjs";
        if (!script.isEmpty() && !java.nio.file.Files.isRegularFile(java.nio.file.Path.of(script))) {
            return "Server script not found: " + script;
        }
        for (String c : configs) {
            if (!java.nio.file.Files.isRegularFile(java.nio.file.Path.of(c))) return "Config not found: " + c;
        }
        return null;
    }

    public void append(String line) {
        String ts = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        SwingUtilities.invokeLater(() -> {
            log.append("[" + ts + "] " + line + "\n");
            log.setCaretPosition(log.getDocument().getLength());
        });
    }

    private void setStatus(boolean ok, String text) {
        SwingUtilities.invokeLater(() -> {
            status.setText((ok ? "● " : "○ ") + text);
            status.setForeground(ok ? new java.awt.Color(0x18, 0x80, 0x38) : java.awt.Color.GRAY);
        });
    }
}
