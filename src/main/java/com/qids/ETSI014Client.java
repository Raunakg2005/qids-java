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
import java.util.Map;

/**
 * Standard client for ETSI GS QKD 014 Key Delivery REST API.
 *
 * Communicates with ETSI-compliant Quantum Key Management Systems (KMS)
 * to retrieve synchronized key material for quantum-proof message signing.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class ETSI014Client {

    private final String baseUrl;
    private final String sourceSaeId;
    private final String destinationSaeId;
    private final HttpClient httpClient;

    public ETSI014Client(String baseUrl, String sourceSaeId, String destinationSaeId) {
        this(baseUrl, sourceSaeId, destinationSaeId, Duration.ofSeconds(10));
    }

    public ETSI014Client(String baseUrl, String sourceSaeId, String destinationSaeId, Duration timeout) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.sourceSaeId = sourceSaeId;
        this.destinationSaeId = destinationSaeId;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
    }

    /**
     * Query status and key availability from the KMS appliance.
     */
    public ETSIStatus getStatus() throws IOException, InterruptedException {
        String url = String.format("%s/api/v1/keys/%s/status", baseUrl, destinationSaeId);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .header("Accept", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("ETSI KMS returned HTTP " + response.statusCode() + ": " + response.body());
        }

        Map<String, Object> body = parseResponse(response.body());
        ETSIStatus status = new ETSIStatus();
        status.setSourceSaeId(Json.string(body, "source_SAE_ID", sourceSaeId));
        status.setDestinationSaeId(Json.string(body, "destination_SAE_ID", destinationSaeId));
        status.setSourceKmeId(Json.string(body, "source_KME_ID", ""));
        status.setDestinationKmeId(Json.string(body, "destination_KME_ID", ""));
        status.setKeySize((int) Json.number(body, "key_size", 256L));
        status.setStoredKeyCount((int) Json.number(body, "stored_key_count", 0L));
        status.setMaxKeyCount((int) Json.number(body, "max_key_count", 1000L));
        return status;
    }

    /**
     * Request encryption keys (Alice / Sender side).
     */
    public List<ETSIKey> getEncKeys(int number, int sizeBits) throws IOException, InterruptedException {
        String url = String.format("%s/api/v1/keys/%s/enc_keys", baseUrl, destinationSaeId);
        String jsonPayload = String.format("{\"number\":%d,\"size\":%d}", number, sizeBits);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("ETSI KMS enc_keys returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return parseKeys(response.body(), sizeBits);
    }

    /**
     * Retrieve matching decryption keys by key ID (Bob / Receiver side).
     */
    public List<ETSIKey> getDecKeys(List<String> keyIds) throws IOException, InterruptedException {
        String url = String.format("%s/api/v1/keys/%s/dec_keys", baseUrl, destinationSaeId);

        StringBuilder sb = new StringBuilder("{\"key_IDs\":[");
        for (int i = 0; i < keyIds.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{\"key_ID\":\"").append(escapeJson(keyIds.get(i))).append("\"}");
        }
        sb.append("]}");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .POST(HttpRequest.BodyPublishers.ofString(sb.toString()))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("ETSI KMS dec_keys returned HTTP " + response.statusCode() + ": " + response.body());
        }

        return parseKeys(response.body(), 0);
    }

    /**
     * Keys are read by field name, in any order, alongside any extension
     * fields ETSI GS QKD 014 allows (key_ID_extension, key_extension). The
     * regex this replaced needed key_ID then key and nothing else, so a
     * compliant response with an extension parsed to zero keys, silently.
     */
    static List<ETSIKey> parseKeys(String json, int defaultSizeBits) throws IOException {
        List<ETSIKey> result = new ArrayList<>();
        for (Object item : Json.array(parseResponse(json), "keys")) {
            if (!(item instanceof Map)) continue;
            @SuppressWarnings("unchecked")
            Map<String, Object> key = (Map<String, Object>) item;
            String keyId = Json.string(key, "key_ID", null);
            String rawKey = Json.string(key, "key", null);
            if (keyId == null || rawKey == null) {
                throw new IOException("ETSI KMS returned a key without key_ID or key");
            }
            byte[] keyBytes;
            try {
                keyBytes = Base64.getDecoder().decode(rawKey);
            } catch (IllegalArgumentException e) {
                keyBytes = hexStringToByteArray(rawKey);
            }
            int sizeBits = (defaultSizeBits > 0) ? defaultSizeBits : keyBytes.length * 8;
            result.add(new ETSIKey(keyId, keyBytes, sizeBits));
        }
        return result;
    }

    private static Map<String, Object> parseResponse(String json) throws IOException {
        try {
            return Json.parseObject(json);
        } catch (IllegalArgumentException e) {
            throw new IOException("ETSI KMS returned a response that is not a JSON object: " + e.getMessage(), e);
        }
    }

    private static String escapeJson(String s) {
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

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
