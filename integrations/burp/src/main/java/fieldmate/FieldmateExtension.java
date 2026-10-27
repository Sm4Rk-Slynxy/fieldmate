package fieldmate;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.*;
import javax.swing.border.EmptyBorder;

/** Passive forwarding only. The Burp callback never waits for network or inference. */
public final class FieldmateExtension implements BurpExtension, HttpHandler {
    private record Config(String base, String token, String engagement, String identity, String project, boolean enabled) {}
    private record Pending(Config config, String payload) {}
    private final ArrayBlockingQueue<Pending> queue = new ArrayBlockingQueue<>(200);
    private final AtomicInteger sent = new AtomicInteger();
    private final AtomicInteger failed = new AtomicInteger();
    private final AtomicInteger dropped = new AtomicInteger();
    private volatile Config config = new Config("http://127.0.0.1:8741", "", "", "unlabeled", "", false);
    private final AtomicBoolean importing = new AtomicBoolean();
    private volatile boolean running = true;
    private MontoyaApi api;
    private Thread worker;
    private Timer statusTimer;

    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Fieldmate — passive companion");
        api.http().registerHttpHandler(this);
        SwingUtilities.invokeLater(() -> api.userInterface().registerSuiteTab("Fieldmate", panel()));
        worker = new Thread(this::forward, "fieldmate-forwarder");
        worker.setDaemon(true);
        worker.start();
        api.extension().registerUnloadingHandler(() -> {
            running = false;
            worker.interrupt();
            queue.clear();
            SwingUtilities.invokeLater(() -> { if (statusTimer != null) statusTimer.stop(); });
        });
    }

    private JPanel panel() {
        JPanel panel = new JPanel(new BorderLayout(12,12));
        panel.setBorder(new EmptyBorder(25,25,25,25));
        JPanel fields = new JPanel(new GridLayout(0,2,12,12));
        JTextField base = new JTextField(config.base());
        JPasswordField token = new JPasswordField();
        JTextField engagement = new JTextField();
        JTextField identity = new JTextField("unlabeled");
        JTextField project = new JTextField();
        JCheckBox enabled = new JCheckBox("Forward HTTP traffic", false);
        fields.add(new JLabel("Local Fieldmate URL")); fields.add(base);
        fields.add(new JLabel("Fieldmate token (.fieldmate/token, not Unsloth key)")); fields.add(token);
        fields.add(new JLabel("Engagement ID (from Fieldmate)")); fields.add(engagement);
        fields.add(new JLabel("Identity for subsequent traffic")); fields.add(identity);
        fields.add(new JLabel("Project import ID (from Fieldmate Project review)")); fields.add(project);
        fields.add(new JLabel("Only URLs in Burp Target scope are forwarded")); fields.add(enabled);
        JLabel status = new JLabel("Disabled. Configure, then apply.");
        JButton apply = new JButton("Apply configuration");
        apply.addActionListener(event -> {
            try {
                URI uri = URI.create(base.getText().strip());
                if (!"http".equals(uri.getScheme()) || !List.of("127.0.0.1", "localhost").contains(uri.getHost())
                    || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null
                    || (uri.getPath() != null && !uri.getPath().isEmpty() && !uri.getPath().equals("/"))) {
                    throw new IllegalArgumentException("Use a loopback HTTP Fieldmate URL");
                }
                String eid = UUID.fromString(engagement.getText().strip()).toString();
                String access = new String(token.getPassword()).strip();
                if (access.isEmpty()) access = config.token();
                if (access.isEmpty() || access.contains("\n") || access.contains("\r")) throw new IllegalArgumentException("Add your Fieldmate token");
                String label = identity.getText().strip();
                if (label.isEmpty() || label.length() > 100) throw new IllegalArgumentException("Add an identity label (max 100 characters)");
                String projectId = project.getText().isBlank() ? "" : UUID.fromString(project.getText().strip()).toString();
                config = new Config(base.getText().strip().replaceAll("/+$", ""), access, eid, label, projectId, enabled.isSelected());
                token.setText("");
                status.setText("Applied. Identity labels affect new traffic only; credentials are held in memory.");
            } catch (IllegalArgumentException exception) { status.setText(exception.getMessage()); }
        });
        fields.add(apply); fields.add(status);
        JButton extract = new JButton("Import opened project (saved data only)");
        JLabel importStatus = new JLabel("No scan or target requests. Live forwarding may remain disabled.");
        extract.addActionListener(event -> {
            Config selected = config;
            if (selected.project().isEmpty() || selected.token().isEmpty()) {
                importStatus.setText("Paste the project import ID and apply configuration first.");
                return;
            }
            if (!importing.compareAndSet(false,true)) return;
            extract.setEnabled(false);
            Thread importer = new Thread(() -> {
                try {
                    importProject(selected,importStatus);
                    SwingUtilities.invokeLater(() -> importStatus.setText("Saved data imported. Return to Fieldmate and choose Review project."));
                } catch (Exception exception) {
                    try { post(selected,"/projects/" + selected.project() + "/complete",json(Map.of("failed",true))); } catch (Exception ignored) {}
                    SwingUtilities.invokeLater(() -> importStatus.setText("Import interrupted; partial data retained. Check the local app and retry."));
                } finally {
                    importing.set(false);
                    SwingUtilities.invokeLater(() -> extract.setEnabled(true));
                }
            },"fieldmate-project-reader");
            importer.setDaemon(true);importer.start();
        });
        fields.add(extract);fields.add(importStatus);
        JLabel counts = new JLabel();
        statusTimer = new Timer(1000, event -> counts.setText("Sent: " + sent.get() + "  |  Failed: " + failed.get() + "  |  Dropped: " + dropped.get() + "  |  Queued: " + queue.size()));
        statusTimer.start();
        panel.add(fields, BorderLayout.NORTH);
        panel.add(new JLabel("Passive only: saved history, site map and issue data. Repeater request text is copied manually in Fieldmate; this extension never sends it."), BorderLayout.CENTER);
        panel.add(counts, BorderLayout.SOUTH);
        return panel;
    }

    @Override public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        Config selected = config;
        if (selected.enabled()) {
            try {
                var request = response.initiatingRequest();
                String url = request.url();
                if (api.scope().isInScope(url) && !url.startsWith(selected.base())) {
                    Map<String,Object> requestHeaders = new LinkedHashMap<>();
                    request.headers().stream().limit(30).forEach(header -> requestHeaders.put(clip(header.name(), 100), clip(header.value(), 1000)));
                    Map<String,Object> responseHeaders = new LinkedHashMap<>();
                    response.headers().stream().limit(30).forEach(header -> responseHeaders.put(clip(header.name(), 100), clip(header.value(), 1000)));
                    Map<String,Object> metadata = new LinkedHashMap<>();
                    metadata.put("method", request.method()); metadata.put("url", url);
                    metadata.put("status", response.statusCode());
                    metadata.put("request_headers", requestHeaders); metadata.put("response_headers", responseHeaders);
                    var requestBody = request.body();
                    var responseBody = response.body();
                    metadata.put("request_body", requestBody.subArray(0, Math.min(requestBody.length(),16000)).toString());
                    metadata.put("request_body_truncated", requestBody.length() > 16000);
                    metadata.put("response_body", responseBody.subArray(0, Math.min(responseBody.length(),24000)).toString());
                    metadata.put("response_body_truncated", responseBody.length() > 24000);
                    metadata.put("observed_at", Instant.now().toString());
                    Map<String,Object> record = new LinkedHashMap<>();
                    record.put("kind", "http"); record.put("source", "burp/montoya"); record.put("target", url);
                    record.put("identity", selected.identity()); record.put("content", request.method() + " " + clip(url, 15000) + " → " + response.statusCode());
                    record.put("metadata", metadata);
                    if (!queue.offer(new Pending(selected, json(Map.of("events", List.of(record)))))) dropped.incrementAndGet();
                }
            } catch (Exception exception) { failed.incrementAndGet(); }
        }
        return ResponseReceivedAction.continueWith(response);
    }

    private void forward() {
        while (running) {
            HttpURLConnection connection = null;
            try {
                Pending item = queue.poll(1, TimeUnit.SECONDS);
                if (item == null) continue;
                Config selected = item.config();
                connection = (HttpURLConnection) URI.create(selected.base() + "/api/engagements/" + selected.engagement() + "/events").toURL().openConnection(java.net.Proxy.NO_PROXY);
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(2000); connection.setReadTimeout(5000);
                connection.setRequestMethod("POST"); connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setRequestProperty("Authorization", "Bearer " + selected.token());
                byte[] bytes = item.payload().getBytes(StandardCharsets.UTF_8);
                connection.setFixedLengthStreamingMode(bytes.length);
                try (var output = connection.getOutputStream()) { output.write(bytes); }
                int code = connection.getResponseCode();
                if (code >= 200 && code < 300) sent.incrementAndGet(); else failed.incrementAndGet();
            } catch (InterruptedException exception) { Thread.currentThread().interrupt(); return; }
            catch (Exception exception) { failed.incrementAndGet(); }
            finally { if (connection != null) connection.disconnect(); }
        }
    }

    private static String clip(String value, int max) { return value.length() > max ? value.substring(0,max) : value; }

    private Map<String,Object> savedMetadata(HttpRequest request,HttpResponse response) {
        Map<String,Object> metadata = new LinkedHashMap<>();
        Map<String,Object> requestHeaders = new LinkedHashMap<>(),responseHeaders = new LinkedHashMap<>();
        request.headers().stream().limit(30).forEach(h -> requestHeaders.put(clip(h.name(),100),clip(h.value(),1000)));
        if (response != null) response.headers().stream().limit(30).forEach(h -> responseHeaders.put(clip(h.name(),100),clip(h.value(),1000)));
        metadata.put("url",request.url());metadata.put("method",request.method());
        metadata.put("status",response == null ? 0 : response.statusCode());
        metadata.put("request_headers",requestHeaders);metadata.put("response_headers",responseHeaders);
        var body = request.body();
        metadata.put("request_body",body.subArray(0,Math.min(body.length(),16000)).toString());
        metadata.put("request_body_truncated",body.length()>16000);
        if (response != null) {
            var responseBody = response.body();
            metadata.put("response_body",responseBody.subArray(0,Math.min(responseBody.length(),24000)).toString());
            metadata.put("response_body_truncated",responseBody.length()>24000);
        }
        return metadata;
    }

    private Map<String,Object> savedEvent(Config selected,HttpRequest request,HttpResponse response) {
        Map<String,Object> metadata = savedMetadata(request,response);
        return Map.of("kind","http","target",request.url(),"identity",selected.identity(),"source","burp/project",
            "content",request.method()+" "+request.url()+" → "+metadata.get("status"),"metadata",metadata);
    }

    private void importProject(Config selected,JLabel status) throws Exception {
        List<Map<String,Object>> batch = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int messages=0,issues=0;
        for (var item : api.proxy().history()) {
            if (!running) throw new InterruptedException();
            HttpRequest request = item.finalRequest();
            if (request.url().startsWith(selected.base())) continue;
            Map<String,Object> event=savedEvent(selected,request,item.hasResponse()?item.response():null);
            String key=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json(event).getBytes(StandardCharsets.UTF_8)));
            if(seen.add(key)){batch.add(event);messages++;}
            if(batch.size()>=20){postBatch(selected,batch);batch.clear();}
        }
        for (var item : api.siteMap().requestResponses()) {
            if (!running) throw new InterruptedException();
            if (item.request().url().startsWith(selected.base())) continue;
            Map<String,Object> event=savedEvent(selected,item.request(),item.response());
            String key=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json(event).getBytes(StandardCharsets.UTF_8)));
            if(seen.add(key)){batch.add(event);messages++;}
            if(batch.size()>=20){postBatch(selected,batch);batch.clear();}
        }
        for (var issue : api.siteMap().issues()) {
            if (!running) throw new InterruptedException();
            String target=issue.baseUrl();
            for (var pair : issue.requestResponses()) {
                target=pair.request().url();
                Map<String,Object> event=savedEvent(selected,pair.request(),pair.response());
                String key=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json(event).getBytes(StandardCharsets.UTF_8)));
                if(seen.add(key)){batch.add(event);messages++;}
                if(batch.size()>=20){postBatch(selected,batch);batch.clear();}
            }
            Map<String,Object> metadata = new LinkedHashMap<>();
            metadata.put("scanner","Burp");metadata.put("name",clip(issue.name(),200));
            metadata.put("severity",issue.severity().toString());metadata.put("confidence",issue.confidence().toString());
            metadata.put("detail",clip(issue.detail()==null?"":issue.detail(),20000));
            metadata.put("scanner_claim_only",true);
            batch.add(Map.of("kind","scanner_issue","target",target,"identity",selected.identity(),"source","burp/project","content",clip(issue.name(),200),"metadata",metadata));
            issues++;
            if(batch.size()>=20){postBatch(selected,batch);batch.clear();}
        }
        if(!batch.isEmpty())postBatch(selected,batch);
        post(selected,"/projects/"+selected.project()+"/complete","{}");
    }

    private void postBatch(Config selected,List<Map<String,Object>> batch) throws Exception {
        post(selected,"/projects/"+selected.project()+"/batches",json(Map.of("events",batch)));
    }

    private void post(Config selected,String suffix,String payload) throws Exception {
        HttpURLConnection connection=(HttpURLConnection)URI.create(selected.base()+"/api/engagements/"+selected.engagement()+suffix).toURL().openConnection(java.net.Proxy.NO_PROXY);
        try {
            connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(2000);connection.setReadTimeout(15000);
            connection.setRequestMethod("POST");connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type","application/json");connection.setRequestProperty("Authorization","Bearer "+selected.token());
            byte[] bytes=payload.getBytes(StandardCharsets.UTF_8);connection.setFixedLengthStreamingMode(bytes.length);
            try(var output=connection.getOutputStream()){output.write(bytes);}
            int code=connection.getResponseCode();
            if(code<200||code>=300)throw new java.io.IOException("Local app rejected saved-data import");
        } finally {connection.disconnect();}
    }

    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?,?> map) return "{" + String.join(",", map.entrySet().stream().map(e -> json(e.getKey().toString()) + ":" + json(e.getValue())).toList()) + "}";
        if (value instanceof List<?> list) return "[" + String.join(",", list.stream().map(FieldmateExtension::json).toList()) + "]";
        StringBuilder result = new StringBuilder("\"");
        for (char c : value.toString().toCharArray()) {
            switch(c) {
                case '"' -> result.append("\\\""); case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n"); case '\r' -> result.append("\\r"); case '\t' -> result.append("\\t");
                default -> { if (c < 32) result.append(String.format("\\u%04x", (int)c)); else result.append(c); }
            }
        }
        return result.append('"').toString();
    }
}
