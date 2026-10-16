package com.qids;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Outcome of a QIDS signature verification.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class VerifyResult {
    private String documentId;
    private String status;
    private boolean isValid;
    private double observedErrorRate;
    private double thresholdErrorRate;
    private String reason;
    private String threat = "";
    private double confidence;
    private Map<String, Object> evidence = new LinkedHashMap<>();

    public VerifyResult() {}

    public VerifyResult(String documentId, String status, boolean isValid,
                        double observedErrorRate, double thresholdErrorRate, String reason) {
        this.documentId = documentId;
        this.status = status;
        this.isValid = isValid;
        this.observedErrorRate = observedErrorRate;
        this.thresholdErrorRate = thresholdErrorRate;
        this.reason = reason;
    }

    public String getDocumentId() { return documentId; }
    public void setDocumentId(String documentId) { this.documentId = documentId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public boolean isValid() { return isValid; }
    public void setValid(boolean valid) { isValid = valid; }

    public double getObservedErrorRate() { return observedErrorRate; }
    public void setObservedErrorRate(double observedErrorRate) { this.observedErrorRate = observedErrorRate; }

    public double getThresholdErrorRate() { return thresholdErrorRate; }
    public void setThresholdErrorRate(double thresholdErrorRate) { this.thresholdErrorRate = thresholdErrorRate; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    /**
     * The gateway's threat attribution: benign, forgery, replay,
     * impersonation or unauthorized_verification.
     */
    public String getThreat() { return threat; }
    public void setThreat(String threat) { this.threat = threat; }

    /** The gateway's confidence in the threat attribution, 0 to 1. */
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }

    /** What the gateway's detectors saw, as parsed JSON (read-only). */
    public Map<String, Object> getEvidence() { return Collections.unmodifiableMap(evidence); }
    public void setEvidence(Map<String, Object> evidence) {
        this.evidence = evidence == null ? new LinkedHashMap<>() : new LinkedHashMap<>(evidence);
    }
}
