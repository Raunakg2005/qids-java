package com.qids;

import java.util.Map;
import java.util.Objects;

/**
 * The "pqc" object of a sign response or an audit receipt: an ML-DSA
 * (FIPS 204) signature over a statement about the signed document. Check it
 * offline with {@link PQCVerifier#verifyPqcReceipt}.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class PQCReceipt {
    private final String algorithm;
    private final String keyId;
    private final String statement;
    private final String signature;

    /**
     * @param algorithm "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87"
     * @param keyId     the first 32 hex characters of SHA-256 over the raw public key
     * @param statement base64 of the exact signed bytes (canonical JSON)
     * @param signature base64 ML-DSA signature over the statement's bytes
     */
    public PQCReceipt(String algorithm, String keyId, String statement, String signature) {
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.statement = statement;
        this.signature = signature;
    }

    /** The receipt in a parsed JSON object; absent fields are null. */
    static PQCReceipt fromJson(Map<String, Object> obj) {
        return new PQCReceipt(Json.string(obj, "algorithm", null), Json.string(obj, "key_id", null),
                Json.string(obj, "statement", null), Json.string(obj, "signature", null));
    }

    public String getAlgorithm() { return algorithm; }

    public String getKeyId() { return keyId; }

    /** Base64 of the exact signed bytes. */
    public String getStatement() { return statement; }

    /** Base64 ML-DSA signature. */
    public String getSignature() { return signature; }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof PQCReceipt)) return false;
        PQCReceipt r = (PQCReceipt) o;
        return Objects.equals(algorithm, r.algorithm) && Objects.equals(keyId, r.keyId)
                && Objects.equals(statement, r.statement) && Objects.equals(signature, r.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm, keyId, statement, signature);
    }

    @Override
    public String toString() {
        return "PQCReceipt{algorithm=" + algorithm + ", keyId=" + keyId + "}";
    }
}
