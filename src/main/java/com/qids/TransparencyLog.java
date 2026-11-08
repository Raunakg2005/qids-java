package com.qids;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Offline checks of a tenant's transparency log (RFC 9162): signed tree
 * heads, inclusion proofs and consistency proofs. Nothing here contacts the
 * gateway; {@link QIDSClient#getTreeHead}, {@link QIDSClient#getInclusionProof}
 * and {@link QIDSClient#getConsistencyProof} fetch what these check.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class TransparencyLog {

    /** The FIPS 204 context string the gateway signs tree heads under. */
    public static final String CONTEXT = "qids-sth-v1";

    private static final byte[] CONTEXT_BYTES = CONTEXT.getBytes(StandardCharsets.US_ASCII);

    private TransparencyLog() {}

    /** A signed tree head, as GET /api/v1/tlog/&lt;tenant&gt;/sth returns it. */
    public static final class SignedTreeHead {
        private final String statement;
        private final String signature;

        public SignedTreeHead(String statement, String signature) {
            this.statement = statement;
            this.signature = signature;
        }

        static SignedTreeHead fromJson(Map<String, Object> obj) {
            return new SignedTreeHead(Json.string(obj, "statement", null), Json.string(obj, "signature", null));
        }

        /** Base64 of the exact signed bytes. */
        public String getStatement() { return statement; }

        /** Base64 ML-DSA signature over the statement's bytes. */
        public String getSignature() { return signature; }
    }

    /** What a verified tree head says. */
    public static final class TreeHeadClaims {
        private final Map<String, Object> claims;
        private final byte[] statement;

        TreeHeadClaims(Map<String, Object> claims, byte[] statement) {
            this.claims = Collections.unmodifiableMap(claims);
            this.statement = statement.clone();
        }

        public String getTenantId() { return Json.string(claims, "tenant_id", ""); }

        public long getTreeSize() { return Json.number(claims, "tree_size", 0L); }

        /** Hex SHA-256 root of the tenant's log at {@link #getTreeSize()}. */
        public String getRootHash() { return Json.string(claims, "root_hash", ""); }

        public long getTimestampMs() { return Json.number(claims, "timestamp_ms", 0L); }

        public String getAlgorithm() { return Json.string(claims, "alg", ""); }

        public String getKeyId() { return Json.string(claims, "kid", ""); }

        /** Every field of the statement, as signed. */
        public Map<String, Object> asMap() { return claims; }

        /** The exact signed bytes. */
        public byte[] getStatement() { return statement.clone(); }
    }

    /** An inclusion proof: GET /api/v1/tlog/&lt;tenant&gt;/inclusion. Hashes in hex. */
    public static final class InclusionProof {
        private final long index;
        private final long treeSize;
        private final String leafHash;
        private final List<String> auditPath;

        InclusionProof(long index, long treeSize, String leafHash, List<String> auditPath) {
            this.index = index;
            this.treeSize = treeSize;
            this.leafHash = leafHash;
            this.auditPath = Collections.unmodifiableList(auditPath);
        }

        public long getIndex() { return index; }

        public long getTreeSize() { return treeSize; }

        public String getLeafHash() { return leafHash; }

        public List<String> getAuditPath() { return auditPath; }
    }

    /** A consistency proof: GET /api/v1/tlog/&lt;tenant&gt;/consistency. Hashes in hex. */
    public static final class ConsistencyProof {
        private final long first;
        private final long second;
        private final List<String> proof;

        ConsistencyProof(long first, long second, List<String> proof) {
            this.first = first;
            this.second = second;
            this.proof = Collections.unmodifiableList(proof);
        }

        public long getFirst() { return first; }

        public long getSecond() { return second; }

        public List<String> getProof() { return proof; }
    }

    private static QIDSVerificationException reject(QIDSVerificationException.Reason reason, String message) {
        return new QIDSVerificationException(reason, message, "transparency-log check");
    }

    /** The transparency-log leaf hash of a receipt: SHA-256(0x00 || statement). */
    public static byte[] receiptLeafHash(PQCReceipt pqc) throws QIDSVerificationException {
        byte[] statement = pqc == null ? null : PQCVerifier.decodeBase64(pqc.getStatement());
        if (statement == null) {
            throw reject(QIDSVerificationException.Reason.MALFORMED_TREE_HEAD,
                    "the receipt has no valid base64 statement");
        }
        MessageDigest h = sha256();
        h.update((byte) 0);
        h.update(statement);
        return h.digest();
    }

    /**
     * RFC 9162 2.1.3.2: check that {@code leafHash} is entry {@code index} of
     * the tree of {@code treeSize} entries whose root is {@code rootHash}.
     *
     * @throws QIDSVerificationException if it is not; its reason names the check
     */
    public static void verifyInclusion(byte[] leafHash, long index, long treeSize, List<byte[]> auditPath,
                                       byte[] rootHash) throws QIDSVerificationException {
        if (index < 0 || index >= treeSize) {
            throw reject(QIDSVerificationException.Reason.INDEX_OUT_OF_RANGE, "leaf index outside the tree");
        }
        long fn = index;
        long sn = treeSize - 1;
        byte[] r = leafHash;
        for (byte[] p : auditPath) {
            if (sn == 0) throw reject(QIDSVerificationException.Reason.PROOF_TOO_LONG, "inclusion proof is too long");
            if ((fn & 1) == 1 || fn == sn) {
                r = node(p, r);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                r = node(r, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        if (sn != 0 || !Arrays.equals(r, rootHash)) {
            throw reject(QIDSVerificationException.Reason.ROOT_MISMATCH,
                    "inclusion proof does not lead to the tree head's root");
        }
    }

    /**
     * RFC 9162 2.1.4.2: check that the tree of {@code secondSize} entries
     * extends the tree of {@code firstSize}, rewriting nothing. This is the
     * check a monitor runs between successive tree heads; a failure means the
     * log forked or an entry changed.
     *
     * @throws QIDSVerificationException if it does not; its reason names the check
     */
    public static void verifyConsistency(long firstSize, long secondSize, byte[] firstRoot, byte[] secondRoot,
                                         List<byte[]> proof) throws QIDSVerificationException {
        if (firstSize <= 0 || firstSize > secondSize) {
            throw reject(QIDSVerificationException.Reason.BAD_SIZES, "need 0 < first_size <= second_size");
        }
        if (firstSize == secondSize) {
            if (!proof.isEmpty() || !Arrays.equals(firstRoot, secondRoot)) {
                throw reject(QIDSVerificationException.Reason.FORK, "same size, different roots: the log forked");
            }
            return;
        }
        if (proof.isEmpty()) throw reject(QIDSVerificationException.Reason.EMPTY_PROOF, "empty consistency proof");
        List<byte[]> path = new ArrayList<>(proof);
        // A first tree whose size is a power of two is a complete subtree: its root starts the path.
        if ((firstSize & (firstSize - 1)) == 0) path.add(0, firstRoot);
        long fn = firstSize - 1;
        long sn = secondSize - 1;
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }
        byte[] fr = path.get(0);
        byte[] sr = path.get(0);
        for (byte[] c : path.subList(1, path.size())) {
            if (sn == 0) {
                throw reject(QIDSVerificationException.Reason.PROOF_TOO_LONG, "consistency proof is too long");
            }
            if ((fn & 1) == 1 || fn == sn) {
                fr = node(c, fr);
                sr = node(c, sr);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>= 1;
                    sn >>= 1;
                }
            } else {
                sr = node(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        if (sn != 0 || !Arrays.equals(fr, firstRoot) || !Arrays.equals(sr, secondRoot)) {
            throw reject(QIDSVerificationException.Reason.INCONSISTENT,
                    "the logs are not consistent: the log forked or an entry changed");
        }
    }

    /**
     * Check a signed tree head's ML-DSA signature offline and return its claims.
     *
     * <p>The checks, in order (those of the Python SDK's verify_tree_head):
     * the signature over the statement's exact bytes under the
     * {@value #CONTEXT} context; that the statement is a tree head (type
     * "qids-sth") naming this key's parameter set and id; and, if given, the
     * tenant.
     *
     * @param sth          the tree head ({@link QIDSClient#getTreeHead})
     * @param publicKeyPem the tenant's key, from a source you trust
     *                     ({@link QIDSClient#getPqcKeys} once, then pinned)
     * @param tenantId     the tenant the log must belong to; null to skip
     * @throws QIDSVerificationException on any failed check; its reason names it
     */
    public static TreeHeadClaims verifyTreeHead(SignedTreeHead sth, String publicKeyPem, String tenantId)
            throws QIDSVerificationException {
        PQCVerifier.MLDSAKey key;
        try {
            key = PQCVerifier.parsePublicKey(publicKeyPem);
        } catch (QIDSVerificationException e) {
            throw reject(QIDSVerificationException.Reason.INVALID_KEY, e.getMessage());
        }
        byte[] statement = sth == null ? null : PQCVerifier.decodeBase64(sth.getStatement());
        byte[] signature = sth == null ? null : PQCVerifier.decodeBase64(sth.getSignature());
        if (statement == null || signature == null) {
            throw reject(QIDSVerificationException.Reason.MALFORMED_TREE_HEAD,
                    "malformed tree head: no valid base64 statement and signature");
        }
        if (!PQCVerifier.verifySignature(key.parameters, statement, signature, CONTEXT_BYTES)) {
            throw reject(QIDSVerificationException.Reason.BAD_SIGNATURE,
                    "tree head signature does not verify under this key");
        }
        Map<String, Object> claims;
        try {
            claims = Json.parseObject(new String(statement, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw reject(QIDSVerificationException.Reason.MALFORMED_TREE_HEAD,
                    "malformed tree head: the statement is not a JSON object");
        }
        String kid = hex(sha256().digest(key.raw)).substring(0, 32);
        if (!"qids-sth".equals(claims.get("type")) || !key.algorithm.equals(claims.get("alg"))
                || !kid.equals(claims.get("kid"))) {
            throw reject(QIDSVerificationException.Reason.KEY_MISMATCH,
                    "the tree head names a different key, algorithm or type");
        }
        if (tenantId != null && !tenantId.equals(claims.get("tenant_id"))) {
            throw reject(QIDSVerificationException.Reason.TENANT_MISMATCH,
                    "the tree head belongs to a different tenant");
        }
        return new TreeHeadClaims(claims, statement);
    }

    /** Hex hashes (a proof's path) as bytes. */
    public static List<byte[]> decodeHashes(List<String> hexHashes) {
        List<byte[]> out = new ArrayList<>(hexHashes.size());
        for (String h : hexHashes) out.add(unhex(h));
        return out;
    }

    /** One hex hash as bytes. */
    public static byte[] unhex(String hex) {
        if (hex == null || hex.length() % 2 != 0) throw new IllegalArgumentException("not a hex hash");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("not a hex hash");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /** RFC 9162 interior node: SHA-256(0x01 || left || right). */
    private static byte[] node(byte[] left, byte[] right) {
        MessageDigest h = sha256();
        h.update((byte) 1);
        h.update(left);
        h.update(right);
        return h.digest();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
