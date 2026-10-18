package com.qids;

import java.util.Map;

/**
 * One of a tenant's published ML-DSA public keys, from
 * {@link QIDSClient#getPqcKeys(String)}.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class PQCPublicKey {
    private final String keyId;
    private final String algorithm;
    private final String status;
    private final String publicKeyPem;
    private final double createdAt;
    private final Double retiredAt;

    PQCPublicKey(String keyId, String algorithm, String status, String publicKeyPem,
                 double createdAt, Double retiredAt) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.status = status;
        this.publicKeyPem = publicKeyPem;
        this.createdAt = createdAt;
        this.retiredAt = retiredAt;
    }

    static PQCPublicKey fromJson(Map<String, Object> obj) {
        Object retired = obj.get("retired_at");
        return new PQCPublicKey(Json.string(obj, "key_id", ""), Json.string(obj, "algorithm", ""),
                Json.string(obj, "status", ""), Json.string(obj, "public_key_pem", ""),
                Json.decimal(obj, "created_at", 0.0),
                retired instanceof Number ? ((Number) retired).doubleValue() : null);
    }

    public String getKeyId() { return keyId; }

    public String getAlgorithm() { return algorithm; }

    /**
     * "active" or "retired". Retired keys stay published so that receipts
     * signed with them stay verifiable.
     */
    public String getStatus() { return status; }

    /** The key as PEM SubjectPublicKeyInfo, for {@link PQCVerifier#verifyPqcReceipt}. */
    public String getPublicKeyPem() { return publicKeyPem; }

    /** Unix time, seconds. */
    public double getCreatedAt() { return createdAt; }

    /** Unix time, seconds; null while the key is active. */
    public Double getRetiredAt() { return retiredAt; }

    @Override
    public String toString() {
        return "PQCPublicKey{keyId=" + keyId + ", algorithm=" + algorithm + ", status=" + status + "}";
    }
}
