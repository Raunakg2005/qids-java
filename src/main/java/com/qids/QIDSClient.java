package com.qids;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Enterprise client for the Quantum Intrusion Detection System (QIDS).
 *
 * Supports both high-level network daemon signing/verification and
 * direct in-process cryptographic operations.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QIDSClient {

    private final String serviceUrl;
    private final String nodeId;
    /** Gateway API key (sk_live_... / sk_test_...). Every /api/v1 call needs it. */
    private final String apiKey;
    private final HttpClient httpClient;

    /**
     * @deprecated the Gateway requires an API key; use
     *             {@link #QIDSClient(String, String, String)}.
     */
    @Deprecated
    public QIDSClient(String serviceUrl, String nodeId) {
        this(serviceUrl, nodeId, null, Duration.ofSeconds(10));
    }

    public QIDSClient(String serviceUrl, String nodeId, String apiKey) {
        this(serviceUrl, nodeId, apiKey, Duration.ofSeconds(10));
    }

    public QIDSClient(String serviceUrl, String nodeId, Duration timeout) {
        this(serviceUrl, nodeId, null, timeout);
    }

    public QIDSClient(String serviceUrl, String nodeId, String apiKey, Duration timeout) {
        this.serviceUrl = (serviceUrl != null && serviceUrl.endsWith("/"))
                ? serviceUrl.substring(0, serviceUrl.length() - 1)
                : serviceUrl;
        this.nodeId = nodeId;
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
    }

    /**
     * Locally compute a 64-bit quantum authentication tag using Toeplitz LFSR universal hashing.
     */
    public long computeTag(byte[] payload, long polyLo, long seed) {
        return ToeplitzHash.hash64(payload, polyLo, seed);
    }

    /**
     * Locally verify a quantum authentication tag with constant-time security.
     */
    public boolean verifyTag(byte[] payload, long expectedTag, long polyLo, long seed) {
        long computed = computeTag(payload, polyLo, seed);
        byte[] expectedBytes = toBytes(expectedTag);
        byte[] computedBytes = toBytes(computed);
        return ConstantTime.ctEqual(expectedBytes, computedBytes);
    }

    /**
     * Submit a payload to the QIDS daemon to generate quantum-safe signatures.
     *
     * The payload travels as payload_b64, its exact bytes. Earlier versions sent
     * new String(payload, UTF_8), which replaces every malformed byte with
     * U+FFFD, so two different binary documents reached the gateway as the same
     * text and a signature over one verified the other.
     */
    public SignResult sign(String docId, byte[] payload, List<String> recipients) throws IOException, InterruptedException {
        String url = serviceUrl + "/api/v1/sign";
        String payloadB64 = Base64.getEncoder().encodeToString(payload != null ? payload : new byte[0]);

        StringBuilder sb = new StringBuilder();
        sb.append("{")
          .append("\"document_id\":\"").append(escapeJson(docId)).append("\",")
          .append("\"payload_b64\":\"").append(payloadB64).append("\",")
          .append("\"recipients\":[");
        for (int i = 0; i < recipients.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(recipients.get(i))).append("\"");
        }
        sb.append("]}");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(sb.toString()))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + (apiKey == null ? "" : apiKey))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("QIDS sign returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return parseSignResult(response.body(), docId);
    }

    /**
     * Submit a signature tag to the QIDS daemon for validation.
     */
    public VerifyResult verify(String docId, byte[] payload, String tag, String keyId) throws IOException, InterruptedException {
        String url = serviceUrl + "/api/v1/verify";
        String payloadB64 = Base64.getEncoder().encodeToString(payload != null ? payload : new byte[0]);

        String json = String.format("{\"document_id\":\"%s\",\"payload_b64\":\"%s\",\"hash_tag\":\"%s\",\"key_id\":\"%s\"}",
                escapeJson(docId), payloadB64, escapeJson(tag), escapeJson(keyId));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("Authorization", "Bearer " + (apiKey == null ? "" : apiKey))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("QIDS verify returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return parseVerifyResult(response.body(), docId);
    }

    private static byte[] toBytes(long val) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (val & 0xFF);
            val >>>= 8;
        }
        return b;
    }

    /** JSON string escaping per RFC 8259: quote, backslash, and every control character. */
    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static SignResult parseSignResult(String json, String defaultDocId) {
        SignResult res = new SignResult();
        res.setDocumentId(defaultDocId);
        res.setDocumentHash(extractJsonString(json, "document_hash", ""));
        res.setAlgorithm(extractJsonString(json, "algorithm", "QIDS-Toeplitz-SPRT-v1"));
        res.setSignedAtUtcMs(System.currentTimeMillis());

        List<SignatureTag> tags = new ArrayList<>();
        Pattern p = Pattern.compile("\\{\\s*\"recipient_sae_id\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"hash_tag\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"tag_length_bits\"\\s*:\\s*([0-9]+)\\s*,\\s*\"key_id\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
        Matcher m = p.matcher(json);
        while (m.find()) {
            tags.add(new SignatureTag(m.group(1), m.group(2), Integer.parseInt(m.group(3)), m.group(4)));
        }
        res.setSignatureTags(tags);
        return res;
    }

    private static VerifyResult parseVerifyResult(String json, String defaultDocId) {
        VerifyResult res = new VerifyResult();
        res.setDocumentId(defaultDocId);
        // Fail closed: a response without a status must not read as ACCEPTED.
        res.setStatus(extractJsonString(json, "status", "UNKNOWN"));
        res.setValid(json.contains("\"is_valid\":true") || json.contains("\"is_valid\": true"));
        res.setReason(extractJsonString(json, "reason", ""));
        return res;
    }

    private static String extractJsonString(String json, String field, String defaultValue) {
        Pattern p = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : defaultValue;
    }
}
