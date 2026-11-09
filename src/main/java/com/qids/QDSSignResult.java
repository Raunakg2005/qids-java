package com.qids;

import java.util.List;
import java.util.Map;

/**
 * A signature made in QDS mode (POST /api/v1/qds/sign): no trusted dealer.
 *
 * The gateway keeps no share; each holder verifies on its own verifier node
 * ({@link VerifierNode}). The envelope is what a holder's node needs besides
 * the document, and is not secret. A preview: not in a gateway release yet.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QDSSignResult {
    private final String documentId;
    private final String documentHash;
    private final String sigId;
    private final Map<String, Object> envelope;
    private final Map<String, Object> delivered;
    private final long signedAtUtcMs;
    private final List<Object> entropySource;
    private final boolean qkdBacked;
    private final PQCReceipt pqc;

    QDSSignResult(String documentId, String documentHash, String sigId, Map<String, Object> envelope,
                  Map<String, Object> delivered, long signedAtUtcMs, List<Object> entropySource,
                  boolean qkdBacked, PQCReceipt pqc) {
        this.documentId = documentId;
        this.documentHash = documentHash;
        this.sigId = sigId;
        this.envelope = envelope;
        this.delivered = delivered;
        this.signedAtUtcMs = signedAtUtcMs;
        this.entropySource = entropySource;
        this.qkdBacked = qkdBacked;
        this.pqc = pqc;
    }

    public String getDocumentId() { return documentId; }
    public String getDocumentHash() { return documentHash; }
    public String getSigId() { return sigId; }
    /** Pass to {@link VerifierNode#verify} as it is. */
    public Map<String, Object> getEnvelope() { return envelope; }
    /** Per holder: "stored", "not_configured", "unreachable: ...", "refused: ...". */
    public Map<String, Object> getDelivered() { return delivered; }
    public long getSignedAtUtcMs() { return signedAtUtcMs; }
    public List<Object> getEntropySource() { return entropySource; }
    public boolean isQkdBacked() { return qkdBacked; }
    /** The ML-DSA receipt; check it with {@link PQCVerifier}. */
    public PQCReceipt getPqc() { return pqc; }
}
