package com.qids;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Offline checks of witnesses' co-signatures on a tenant's tree heads.
 * Nothing here contacts the gateway; {@link QIDSClient#getCosignedTreeHead}
 * fetches what these check.
 *
 * <p>A gateway can show one history to a monitor and another to everyone
 * else, each signed with the tenant's key, which the operator holds. A
 * witness ({@code python -m qids.witness}) co-signs a head only if it extends
 * the last one it co-signed, so a head that enough witnesses you trust
 * co-signed is on the one history they all saw.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class Witnesses {

    /** The FIPS 204 context string witnesses sign co-signatures under. */
    public static final String CONTEXT = "qids-witness-v1";

    private static final byte[] CONTEXT_BYTES = CONTEXT.getBytes(StandardCharsets.US_ASCII);

    private Witnesses() {}

    /** One witness's co-signature on a tree head. */
    public static final class Cosignature {
        private final String witness;
        private final String statement;
        private final String signature;

        public Cosignature(String witness, String statement, String signature) {
            this.witness = witness;
            this.statement = statement;
            this.signature = signature;
        }

        static Cosignature fromJson(Object value) {
            if (!(value instanceof Map)) return new Cosignature(null, null, null);
            @SuppressWarnings("unchecked")
            Map<String, Object> obj = (Map<String, Object>) value;
            return new Cosignature(Json.string(obj, "witness", null), Json.string(obj, "statement", null),
                    Json.string(obj, "signature", null));
        }

        /** The witness key's id: the first 32 hex characters of SHA-256 over the raw key. */
        public String getWitness() { return witness; }

        /** Base64 of the exact signed bytes. */
        public String getStatement() { return statement; }

        /** Base64 ML-DSA-65 signature over the statement's bytes. */
        public String getSignature() { return signature; }
    }

    /** A tree head and the co-signatures the gateway holds for it. */
    public static final class CosignedHead {
        private final TransparencyLog.SignedTreeHead sth;
        private final List<Cosignature> cosignatures;

        public CosignedHead(TransparencyLog.SignedTreeHead sth, List<Cosignature> cosignatures) {
            this.sth = sth;
            this.cosignatures = Collections.unmodifiableList(new ArrayList<>(cosignatures));
        }

        static CosignedHead fromJson(Map<String, Object> obj) {
            List<Cosignature> cosigs = new ArrayList<>();
            for (Object c : Json.array(obj, "cosignatures")) cosigs.add(Cosignature.fromJson(c));
            return new CosignedHead(TransparencyLog.SignedTreeHead.fromJson(Json.object(obj, "sth")), cosigs);
        }

        public TransparencyLog.SignedTreeHead getSth() { return sth; }

        public List<Cosignature> getCosignatures() { return cosignatures; }
    }

    /**
     * GET /api/v1/tlog/&lt;tenant&gt;/cosigned: recent co-signed heads, largest
     * first. An older gateway served only the largest, at the top level.
     */
    public static final class CosignedTreeHeads {
        private final List<CosignedHead> heads;

        public CosignedTreeHeads(List<CosignedHead> heads) {
            this.heads = Collections.unmodifiableList(new ArrayList<>(heads));
        }

        /** Read the route's JSON body, as {@link Json#parseObject} returns it. */
        @SuppressWarnings("unchecked")
        public static CosignedTreeHeads fromJson(Map<String, Object> obj) {
            List<CosignedHead> heads = new ArrayList<>();
            Object list = obj.get("heads");
            if (list == null) {
                heads.add(CosignedHead.fromJson(obj));             // one head, at the top level
            } else if (list instanceof List) {
                for (Object h : (List<Object>) list) {
                    if (h instanceof Map) heads.add(CosignedHead.fromJson((Map<String, Object>) h));
                }
            }
            return new CosignedTreeHeads(heads);
        }

        public List<CosignedHead> getHeads() { return heads; }
    }

    /** What a verified co-signature says. */
    public static final class CosignatureClaims {
        private final Map<String, Object> claims;

        CosignatureClaims(Map<String, Object> claims) {
            this.claims = Collections.unmodifiableMap(claims);
        }

        public String getWitness() { return Json.string(claims, "witness", ""); }

        public String getTenantId() { return Json.string(claims, "tenant_id", ""); }

        public long getTreeSize() { return Json.number(claims, "tree_size", 0L); }

        public String getRootHash() { return Json.string(claims, "root_hash", ""); }

        public String getLogKeyId() { return Json.string(claims, "log_kid", ""); }

        /** When the witness co-signed, by its own clock. */
        public long getCosignedAtMs() { return Json.number(claims, "cosigned_at_ms", 0L); }

        /** Every field of the statement, as signed. */
        public Map<String, Object> asMap() { return claims; }
    }

    /** A tree head that a quorum of trusted witnesses co-signed. */
    public static final class CosignedTreeHeadClaims {
        private final TransparencyLog.TreeHeadClaims head;
        private final List<String> witnesses;
        private final long cosignedAtMs;

        CosignedTreeHeadClaims(TransparencyLog.TreeHeadClaims head, List<String> witnesses, long cosignedAtMs) {
            this.head = head;
            this.witnesses = Collections.unmodifiableList(witnesses);
            this.cosignedAtMs = cosignedAtMs;
        }

        /** The verified tree head. */
        public TransparencyLog.TreeHeadClaims getHead() { return head; }

        public long getTreeSize() { return head.getTreeSize(); }

        public String getRootHash() { return head.getRootHash(); }

        /** The ids of the trusted witnesses whose co-signatures verified, sorted. */
        public List<String> getWitnesses() { return witnesses; }

        /**
         * The quorum-th most recent of their co-signing times, by the
         * witnesses' clocks: how fresh the witnessing is. The head's own
         * timestamp is the operator's.
         */
        public long getCosignedAtMs() { return cosignedAtMs; }
    }

    private static final class WitnessKey {
        final PQCVerifier.MLDSAKey key;
        final String kid;

        WitnessKey(PQCVerifier.MLDSAKey key, String kid) {
            this.key = key;
            this.kid = kid;
        }
    }

    private static QIDSVerificationException reject(QIDSVerificationException.Reason reason, String message) {
        return new QIDSVerificationException(reason, message, "transparency-log check");
    }

    /** A trusted witness key: ML-DSA-65 only, as qids.witness requires. */
    private static WitnessKey witnessKey(String pem) throws QIDSVerificationException {
        PQCVerifier.MLDSAKey key;
        try {
            key = PQCVerifier.parsePublicKey(pem);
        } catch (QIDSVerificationException e) {
            throw reject(QIDSVerificationException.Reason.INVALID_KEY, e.getMessage());
        }
        if (!"ML-DSA-65".equals(key.algorithm)) {
            throw reject(QIDSVerificationException.Reason.INVALID_KEY, "a witness key must be ML-DSA-65");
        }
        try {
            String kid = TransparencyLog.hex(MessageDigest.getInstance("SHA-256").digest(key.raw)).substring(0, 32);
            return new WitnessKey(key, kid);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java platform", e);
        }
    }

    private static CosignatureClaims check(Cosignature cosig, WitnessKey key, TransparencyLog.TreeHeadClaims head)
            throws QIDSVerificationException {
        byte[] statement = cosig == null ? null : PQCVerifier.decodeBase64(cosig.getStatement());
        byte[] signature = cosig == null ? null : PQCVerifier.decodeBase64(cosig.getSignature());
        if (statement == null || signature == null) {
            throw reject(QIDSVerificationException.Reason.BAD_COSIGNATURE, "malformed co-signature");
        }
        if (!PQCVerifier.verifySignature(key.key.parameters, statement, signature, CONTEXT_BYTES)) {
            throw reject(QIDSVerificationException.Reason.BAD_COSIGNATURE,
                    "co-signature does not verify under this witness key");
        }
        Map<String, Object> body;
        try {
            body = Json.parseObject(new String(statement, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw reject(QIDSVerificationException.Reason.BAD_COSIGNATURE, "malformed co-signature");
        }
        if (!"qids-cosignature".equals(body.get("type")) || !key.kid.equals(body.get("witness"))) {
            throw reject(QIDSVerificationException.Reason.COSIGNATURE_MISMATCH,
                    "the co-signature names another witness or type");
        }
        Map<String, Object> claims = head.asMap();
        for (String name : new String[] {"tenant_id", "tree_size", "root_hash"}) {
            if (!Objects.equals(body.get(name), claims.get(name))) {
                throw reject(QIDSVerificationException.Reason.COSIGNATURE_MISMATCH,
                        "the co-signature is for another head (" + name + ")");
            }
        }
        if (!Objects.equals(body.get("log_kid"), claims.get("kid"))) {
            throw reject(QIDSVerificationException.Reason.COSIGNATURE_MISMATCH,
                    "the co-signature is for a head under another log key");
        }
        if (!(body.get("cosigned_at_ms") instanceof Long)) {
            throw reject(QIDSVerificationException.Reason.BAD_COSIGNATURE, "malformed co-signature: cosigned_at_ms");
        }
        return new CosignatureClaims(new LinkedHashMap<>(body));
    }

    /**
     * Check one witness's co-signature on a tree head that
     * {@link TransparencyLog#verifyTreeHead} returned, and return what the
     * witness signed.
     *
     * <p>The checks (those of the Python SDK's qids.witness.verify_cosignature):
     * an ML-DSA-65 signature over the statement's exact bytes under the
     * {@value #CONTEXT} context; a qids-cosignature statement naming this
     * witness key; the same tenant, tree size and root as the head; and the
     * head's log key.
     *
     * @param witnessPublicKeyPem the witness's ML-DSA-65 key, pinned from a source you trust
     * @throws QIDSVerificationException on any failed check; its reason names it
     */
    public static CosignatureClaims verifyCosignature(Cosignature cosig, String witnessPublicKeyPem,
                                                      TransparencyLog.TreeHeadClaims head)
            throws QIDSVerificationException {
        return check(cosig, witnessKey(witnessPublicKeyPem), head);
    }

    /**
     * Verify the largest tree head that at least {@code quorum} distinct
     * trusted witnesses co-signed.
     *
     * <p>The checks, as the Python SDK's qids.witness.verify_cosigned_tree_head
     * makes them: each head's signature under the log key (and tenant, if
     * given); that no trusted witness key is the log's own key; and each
     * co-signature from a trusted witness, as {@link #verifyCosignature} does.
     * A co-signature that fails counts for nothing, and a witness counts once.
     * The largest head with {@code quorum} witnesses wins: on a busy log the
     * newest head may have only some of them yet.
     *
     * @param cosigned             what {@link QIDSClient#getCosignedTreeHead} returns
     * @param logPublicKeyPem      the tenant's ML-DSA key, pinned
     * @param witnessPublicKeyPems the witness keys you trust, pinned
     * @param quorum               how many distinct trusted witnesses must have co-signed (1 or more)
     * @param tenantId             the tenant the log must belong to; null to skip
     * @throws QIDSVerificationException if no head meets the quorum, or a key is unusable
     * @throws IllegalArgumentException  if {@code quorum} is below 1
     */
    public static CosignedTreeHeadClaims verifyCosignedTreeHead(CosignedTreeHeads cosigned, String logPublicKeyPem,
                                                                List<String> witnessPublicKeyPems, int quorum,
                                                                String tenantId)
            throws QIDSVerificationException {
        if (quorum < 1) throw new IllegalArgumentException("quorum must be at least 1");
        Map<String, WitnessKey> trusted = new LinkedHashMap<>();
        for (String pem : witnessPublicKeyPems) {
            WitnessKey key = witnessKey(pem);
            trusted.put(key.kid, key);
        }
        TransparencyLog.TreeHeadClaims best = null;
        Map<String, Long> bestTimes = null;
        int bestCount = 0;
        String reason = "no co-signed head";
        for (CosignedHead head : cosigned == null ? List.<CosignedHead>of() : cosigned.getHeads()) {
            TransparencyLog.TreeHeadClaims claims;
            try {
                claims = TransparencyLog.verifyTreeHead(head.getSth(), logPublicKeyPem, tenantId);
            } catch (QIDSVerificationException e) {
                reason = e.getMessage();
                continue;
            }
            if (trusted.containsKey(claims.getKeyId())) {
                // The operator holds the log key: as a "witness" it would forge the quorum.
                throw reject(QIDSVerificationException.Reason.WITNESS_IS_LOG_KEY,
                        "a trusted witness key is the log's own key");
            }
            Map<String, Long> times = new TreeMap<>();
            for (Cosignature cosig : head.getCosignatures()) {
                WitnessKey key = cosig.getWitness() == null ? null : trusted.get(cosig.getWitness());
                if (key == null) continue;
                CosignatureClaims body;
                try {
                    body = check(cosig, key, claims);
                } catch (QIDSVerificationException e) {
                    continue;                                       // a bad one counts for nothing
                }
                times.merge(key.kid, body.getCosignedAtMs(), Math::max);
            }
            bestCount = Math.max(bestCount, times.size());
            if (times.size() >= quorum && (best == null || claims.getTreeSize() > best.getTreeSize())) {
                best = claims;
                bestTimes = times;
            }
        }
        if (best == null) {
            throw reject(QIDSVerificationException.Reason.QUORUM_NOT_MET, "no tree head has " + quorum
                    + " valid co-signature(s) from trusted witnesses (at most " + bestCount + "; " + reason + ")");
        }
        List<Long> recent = new ArrayList<>(bestTimes.values());
        recent.sort(Collections.reverseOrder());
        return new CosignedTreeHeadClaims(best, new ArrayList<>(bestTimes.keySet()), recent.get(quorum - 1));
    }
}
