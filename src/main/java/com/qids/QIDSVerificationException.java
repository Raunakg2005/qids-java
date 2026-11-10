package com.qids;

import java.security.GeneralSecurityException;

/**
 * A receipt, tree head, proof or co-signature that failed an offline check in
 * {@link PQCVerifier#verifyPqcReceipt}, {@link TransparencyLog} or {@link Witnesses}.
 * {@link #getReason()} names the check.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QIDSVerificationException extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    /** The checks. Receipts and tree heads share the first ones. */
    public enum Reason {
        /** Not a PEM SubjectPublicKeyInfo ML-DSA public key. */
        INVALID_KEY("invalid_key"),
        /** The statement or signature is missing or not base64. */
        MALFORMED_RECEIPT("malformed_receipt"),
        /** The signature does not verify under this key and context. */
        BAD_SIGNATURE("bad_signature"),
        /** The statement names a different key id (a tree head: or algorithm, or type). */
        KEY_MISMATCH("key_mismatch"),
        /** The statement names a different ML-DSA parameter set. */
        ALGORITHM_MISMATCH("algorithm_mismatch"),
        /** The receipt is for a different document, or not a SHA3-256 hash of one. */
        DOCUMENT_MISMATCH("document_mismatch"),
        /** The receipt or tree head belongs to a different tenant. */
        TENANT_MISMATCH("tenant_mismatch"),
        /** A tree head's statement or signature is missing or not base64, or not JSON. */
        MALFORMED_TREE_HEAD("malformed_tree_head"),
        /** An inclusion proof's leaf index is not below the tree size. */
        INDEX_OUT_OF_RANGE("index_out_of_range"),
        /** A proof has more hashes than the tree needs. */
        PROOF_TOO_LONG("proof_too_long"),
        /** An inclusion proof does not lead to the root. */
        ROOT_MISMATCH("root_mismatch"),
        /** Not 0 &lt; first size &lt;= second size. */
        BAD_SIZES("bad_sizes"),
        /** Two trees of one size with different roots, or a proof between them. */
        FORK("fork"),
        /** Two sizes and no consistency proof. */
        EMPTY_PROOF("empty_proof"),
        /** A consistency proof does not lead to both roots: the log forked or an entry changed. */
        INCONSISTENT("inconsistent"),
        /** A co-signature is malformed, or does not verify under the witness key and context. */
        BAD_COSIGNATURE("bad_cosignature"),
        /** A co-signature names another witness, or another head, tenant or log key. */
        COSIGNATURE_MISMATCH("cosignature_mismatch"),
        /** A trusted witness key is the log's own key, which the operator holds. */
        WITNESS_IS_LOG_KEY("witness_is_log_key"),
        /** No tree head has the quorum of valid co-signatures from distinct trusted witnesses. */
        QUORUM_NOT_MET("quorum_not_met");

        private final String code;

        Reason(String code) {
            this.code = code;
        }

        /** The reason's code, as the other QIDS SDKs name it (e.g. "bad_signature"). */
        public String code() { return code; }
    }

    private final Reason reason;

    QIDSVerificationException(Reason reason, String message) {
        this(reason, message, "receipt");
    }

    QIDSVerificationException(Reason reason, String message, String subject) {
        super("QIDS " + subject + " rejected (" + reason.code() + "): " + message);
        this.reason = reason;
    }

    public Reason getReason() { return reason; }
}
