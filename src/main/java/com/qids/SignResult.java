package com.qids;

import java.util.ArrayList;
import java.util.List;

/**
 * Output of a QIDS signing operation.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class SignResult {
    private String documentId;
    private String documentHash;
    private List<SignatureTag> signatureTags;
    private long signedAtUtcMs;
    private String algorithm;
    private List<String> entropySource = new ArrayList<>();
    private boolean qkdBacked;

    public SignResult() {}

    public SignResult(String documentId, String documentHash, List<SignatureTag> signatureTags,
                      long signedAtUtcMs, String algorithm) {
        this.documentId = documentId;
        this.documentHash = documentHash;
        this.signatureTags = signatureTags;
        this.signedAtUtcMs = signedAtUtcMs;
        this.algorithm = algorithm;
    }

    public String getDocumentId() { return documentId; }
    public void setDocumentId(String documentId) { this.documentId = documentId; }

    public String getDocumentHash() { return documentHash; }
    public void setDocumentHash(String documentHash) { this.documentHash = documentHash; }

    public List<SignatureTag> getSignatureTags() { return signatureTags; }
    public void setSignatureTags(List<SignatureTag> signatureTags) { this.signatureTags = signatureTags; }

    public long getSignedAtUtcMs() { return signedAtUtcMs; }
    public void setSignedAtUtcMs(long signedAtUtcMs) { this.signedAtUtcMs = signedAtUtcMs; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    /**
     * Where the signature's one-time key actually came from: "CSPRNG",
     * "ETSI-GS-QKD-014", or "ETSI-GS-QKD-014-MOCK" (a KMS that declares
     * itself a mock).
     */
    public List<String> getEntropySource() { return entropySource; }
    public void setEntropySource(List<String> entropySource) { this.entropySource = entropySource; }

    /** True only when the key came from an ETSI GS QKD 014 KMS that is not a mock. */
    public boolean isQkdBacked() { return qkdBacked; }
    public void setQkdBacked(boolean qkdBacked) { this.qkdBacked = qkdBacked; }
}
