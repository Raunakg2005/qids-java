package com.qids;

/**
 * ETSI GS QKD 014 Key Delivery status metrics.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class ETSIStatus {
    private String sourceKmeId;
    private String destinationKmeId;
    private String sourceSaeId;
    private String destinationSaeId;
    private int keySize;
    private int storedKeyCount;
    private int maxKeyCount;

    public ETSIStatus() {}

    public ETSIStatus(String sourceKmeId, String destinationKmeId, String sourceSaeId,
                      String destinationSaeId, int keySize, int storedKeyCount, int maxKeyCount) {
        this.sourceKmeId = sourceKmeId;
        this.destinationKmeId = destinationKmeId;
        this.sourceSaeId = sourceSaeId;
        this.destinationSaeId = destinationSaeId;
        this.keySize = keySize;
        this.storedKeyCount = storedKeyCount;
        this.maxKeyCount = maxKeyCount;
    }

    public String getSourceKmeId() { return sourceKmeId; }
    public void setSourceKmeId(String sourceKmeId) { this.sourceKmeId = sourceKmeId; }

    public String getDestinationKmeId() { return destinationKmeId; }
    public void setDestinationKmeId(String destinationKmeId) { this.destinationKmeId = destinationKmeId; }

    public String getSourceSaeId() { return sourceSaeId; }
    public void setSourceSaeId(String sourceSaeId) { this.sourceSaeId = sourceSaeId; }

    public String getDestinationSaeId() { return destinationSaeId; }
    public void setDestinationSaeId(String destinationSaeId) { this.destinationSaeId = destinationSaeId; }

    public int getKeySize() { return keySize; }
    public void setKeySize(int keySize) { this.keySize = keySize; }

    public int getStoredKeyCount() { return storedKeyCount; }
    public void setStoredKeyCount(int storedKeyCount) { this.storedKeyCount = storedKeyCount; }

    public int getMaxKeyCount() { return maxKeyCount; }
    public void setMaxKeyCount(int maxKeyCount) { this.maxKeyCount = maxKeyCount; }
}
