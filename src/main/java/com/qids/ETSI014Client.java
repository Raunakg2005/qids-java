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

        String body = response.body();
        ETSIStatus status = new ETSIStatus();
        status.setSourceSaeId(extractJsonString(body, "source_SAE_ID", sourceSaeId));
        status.setDestinationSaeId(extractJsonString(body, "destination_SAE_ID", destinationSaeId));
        status.setSourceKmeId(extractJsonString(body, "source_KME_ID", ""));
        status.setDestinationKmeId(extractJsonString(body, "destination_KME_ID", ""));
        status.setKeySize(extractJsonInt(body, "key_size", 256));
        status.setStoredKeyCount(extractJsonInt(body, "stored_key_count", 0));
        status.setMaxKeyCount(extractJsonInt(body, "max_key_count", 1000));
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
            sb.append("{\"key_ID\":\"").append(keyIds.get(i)).append("\"}");
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

    private static List<ETSIKey> parseKeys(String json, int defaultSizeBits) {
        List<ETSIKey> result = new ArrayList<>();
        Pattern pattern = Pattern.compile("\\{\\s*\"key_ID\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"key\"\\s*:\\s*\"([^\"]+)\"\\s*\\}");
        Matcher matcher = pattern.matcher(json);
        while (matcher.find()) {
            String keyId = matcher.group(1);
            String rawKey = matcher.group(2);
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

    private static String extractJsonString(String json, String field, String defaultValue) {
        Pattern p = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(json);
        return m.find() ? m.group(1) : defaultValue;
    }

    private static int extractJsonInt(String json, String field, int defaultValue) {
        Pattern p = Pattern.compile("\"" + field + "\"\\s*:\\s*([0-9]+)");
        Matcher m = p.matcher(json);
        return m.find() ? Integer.parseInt(m.group(1)) : defaultValue;
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
