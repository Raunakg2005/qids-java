package com.qids;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A holder's own verifier node (python -m qids.qds.node), in QDS mode.
 *
 * {@link #deliver} needs no credentials: the node checks the signer's tag.
 * {@link #verify} needs the node operator's token, because verifying binds
 * the node's key to the document.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class VerifierNode {
    private final String url;
    private final String token;
    private final Duration timeout;
    private final HttpClient http;

    public VerifierNode(String url, String token) {
        this(url, token, Duration.ofSeconds(30));
    }

    public VerifierNode(String url, String token, Duration timeout) {
        this.url = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        this.token = token;
        this.timeout = timeout;
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    private HttpResponse<String> post(String path, Map<String, Object> body, boolean auth)
            throws IOException, InterruptedException {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(url + path))
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8))
                .header("Content-Type", "application/json");
        if (auth) {
            if (token == null || token.isBlank()) {
                throw new IllegalStateException("verifying on a node needs its operator token");
            }
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Hand the node an envelope. True if it stored it; false if it refused it. */
    public boolean deliver(Map<String, Object> envelope) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("envelope", envelope);
        HttpResponse<String> resp = post("/v1/qds/signatures", body, false);
        if (resp.statusCode() >= 500) throw QIDSException.fromResponse("qds deliver", resp);
        return Json.isTrue(Json.parseObject(resp.body()), "stored");
    }

    /** The node's verdict on {@code document} under {@code envelope}. */
    public QDSVerdict verify(byte[] document, Map<String, Object> envelope) throws IOException, InterruptedException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("document_b64", Base64.getEncoder().encodeToString(document != null ? document : new byte[0]));
        body.put("envelope", envelope);
        HttpResponse<String> resp = post("/v1/qds/verify", body, true);
        if (resp.statusCode() != 200) throw QIDSException.fromResponse("qds verify", resp);
        Map<String, Object> out = Json.parseObject(resp.body());
        return new QDSVerdict(Json.string(out, "holder", ""), Json.string(out, "sig_id", ""),
                Json.isTrue(out, "accepted"), Json.string(out, "reason", ""), Json.string(out, "detail", ""));
    }
}
