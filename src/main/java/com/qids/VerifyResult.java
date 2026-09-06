package com.qids;

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
}
