package com.qids;

import java.security.GeneralSecurityException;

/**
 * A receipt that failed an offline check in
 * {@link PQCVerifier#verifyPqcReceipt}. {@link #getReason()} names the check.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QIDSVerificationException extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    /** The checks, in the order they run. */
    public enum Reason {
        /** Not a PEM SubjectPublicKeyInfo ML-DSA public key. */
        INVALID_KEY("invalid_key"),
        /** The statement or signature is missing or not base64. */
        MALFORMED_RECEIPT("malformed_receipt"),
        /** The signature does not verify under this key and the qids-receipt-v1 context. */
        BAD_SIGNATURE("bad_signature"),
        /** The statement names a different key id. */
        KEY_MISMATCH("key_mismatch"),
        /** The statement names a different ML-DSA parameter set. */
        ALGORITHM_MISMATCH("algorithm_mismatch"),
        /** The receipt is for a different document, or not a SHA3-256 hash of one. */
        DOCUMENT_MISMATCH("document_mismatch"),
        /** The receipt belongs to a different tenant. */
        TENANT_MISMATCH("tenant_mismatch");

        private final String code;

        Reason(String code) {
            this.code = code;
        }

        /** The reason's code, as the other QIDS SDKs name it (e.g. "bad_signature"). */
        public String code() { return code; }
    }

    private final Reason reason;

    QIDSVerificationException(Reason reason, String message) {
        super("QIDS receipt rejected (" + reason.code() + "): " + message);
        this.reason = reason;
    }

    public Reason getReason() { return reason; }
}
