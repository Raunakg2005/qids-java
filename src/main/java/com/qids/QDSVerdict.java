package com.qids;

/**
 * A verifier node's verdict on a document under a QDS envelope.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QDSVerdict {
    private final String holder;
    private final String sigId;
    private final boolean accepted;
    private final String reason;
    private final String detail;

    QDSVerdict(String holder, String sigId, boolean accepted, String reason, String detail) {
        this.holder = holder;
        this.sigId = sigId;
        this.accepted = accepted;
        this.reason = reason;
        this.detail = detail;
    }

    public String getHolder() { return holder; }
    public String getSigId() { return sigId; }
    public boolean isAccepted() { return accepted; }
    public String getReason() { return reason; }
    public String getDetail() { return detail; }
}
