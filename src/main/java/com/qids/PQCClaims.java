package com.qids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * What a verified receipt statement says. Returned by
 * {@link PQCVerifier#verifyPqcReceipt} only after every check passed.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class PQCClaims {
    private final Map<String, Object> claims;
    private final byte[] statement;

    PQCClaims(Map<String, Object> claims, byte[] statement) {
        this.claims = Collections.unmodifiableMap(claims);
        this.statement = statement.clone();
    }

    /** Statement format version ("v"). */
    public int getVersion() { return (int) Json.number(claims, "v", 0L); }

    /** The ML-DSA parameter set ("alg"). */
    public String getAlgorithm() { return Json.string(claims, "alg", ""); }

    /** The signing key's id ("kid"). */
    public String getKeyId() { return Json.string(claims, "kid", ""); }

    public String getTenantId() { return Json.string(claims, "tenant_id", ""); }

    public String getDocumentId() { return Json.string(claims, "document_id", ""); }

    /** Hex SHA3-256 of the document. */
    public String getDocumentHash() { return Json.string(claims, "document_hash", ""); }

    /** Always "SHA3-256" in a receipt that verified. */
    public String getDocumentHashAlg() { return Json.string(claims, "document_hash_alg", ""); }

    public long getSignedAtMs() { return Json.number(claims, "signed_at_ms", 0L); }

    public List<String> getRecipients() {
        List<String> out = new ArrayList<>();
        for (Object r : Json.array(claims, "recipients")) {
            if (r instanceof String) out.add((String) r);
        }
        return Collections.unmodifiableList(out);
    }

    /** The OTUH signature the statement records: algorithm, key_id, signature, signature_bits. */
    public Map<String, Object> getOtuh() { return Collections.unmodifiableMap(Json.object(claims, "otuh")); }

    /** Where the one-time key came from: "CSPRNG", "ETSI-GS-QKD-014" or "ETSI-GS-QKD-014-MOCK". */
    public String getEntropySource() { return Json.string(claims, "entropy_source", ""); }

    /** The ETSI GS QKD 014 key_ID of the one-time key; null when it came from the CSPRNG. */
    public String getKmsKeyId() { return Json.string(claims, "kms_key_id", null); }

    /** Every field of the statement, parsed. */
    public Map<String, Object> asMap() { return claims; }

    /** The exact signed bytes. */
    public byte[] getStatement() { return statement.clone(); }

    @Override
    public String toString() {
        return "PQCClaims" + claims;
    }
}
