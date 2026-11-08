package com.qids;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Offline transparency-log checks against src/test/resources/tlog_vectors.json:
 * signed tree heads, inclusion and consistency proofs from a real gateway, and
 * edits of them, each with the outcome to reach. The QIDS repository generates
 * them (tests/vectors/make_tlog_vectors.py) and holds its Python verifiers to
 * the same outcomes.
 */
class TransparencyLogTest {

    private static Map<String, Object> vectors() throws Exception {
        try (InputStream in = TransparencyLogTest.class.getResourceAsStream("/tlog_vectors.json")) {
            assertNotNull(in, "tlog_vectors.json missing");
            return Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> group(String name) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object v : Json.array(vectors(), name)) out.add((Map<String, Object>) v);
        return out;
    }

    private static List<String> strings(Map<String, Object> v, String key) {
        List<String> out = new ArrayList<>();
        for (Object o : Json.array(v, key)) out.add((String) o);
        return out;
    }

    private static void expect(Map<String, Object> v, TlogCheck check) throws Exception {
        if ("valid".equals(v.get("expect"))) {
            check.run();
            return;
        }
        QIDSVerificationException e = assertThrows(QIDSVerificationException.class, check::run);
        assertEquals(v.get("reason"), e.getReason().code(), e.getMessage());
    }

    @FunctionalInterface
    private interface TlogCheck {
        void run() throws Exception;
    }

    @Test
    void vectorsCoverEveryReason() throws Exception {
        assertEquals(TransparencyLog.CONTEXT, Json.string(vectors(), "context", ""));
        Set<String> reasons = new TreeSet<>();
        for (String g : List.of("tree_heads", "inclusion", "consistency")) {
            for (Map<String, Object> v : group(g)) {
                if ("error".equals(v.get("expect"))) reasons.add((String) v.get("reason"));
            }
        }
        assertEquals(new TreeSet<>(List.of("bad_signature", "bad_sizes", "empty_proof", "fork", "inconsistent",
                "index_out_of_range", "invalid_key", "key_mismatch", "malformed_tree_head", "proof_too_long",
                "root_mismatch", "tenant_mismatch")), reasons);
    }

    @TestFactory
    Stream<DynamicTest> treeHeads() throws Exception {
        return group("tree_heads").stream().map(v -> DynamicTest.dynamicTest(Json.string(v, "name", "?"), () -> {
            TransparencyLog.SignedTreeHead sth = TransparencyLog.SignedTreeHead.fromJson(Json.object(v, "sth"));
            String pem = Json.string(v, "public_key_pem", "");
            String tenant = Json.string(v, "tenant_id", null);
            expect(v, () -> {
                TransparencyLog.TreeHeadClaims claims = TransparencyLog.verifyTreeHead(sth, pem, tenant);
                Map<String, Object> want = Json.object(v, "claims");
                assertEquals(want, claims.asMap());
                assertEquals(Json.number(want, "tree_size", -1L), claims.getTreeSize());
                assertEquals(Json.string(want, "root_hash", ""), claims.getRootHash());
                assertArrayEquals(Base64.getDecoder().decode(sth.getStatement()), claims.getStatement());
            });
        }));
    }

    @TestFactory
    Stream<DynamicTest> inclusionProofs() throws Exception {
        return group("inclusion").stream().map(v -> DynamicTest.dynamicTest(Json.string(v, "name", "?"), () ->
                expect(v, () -> TransparencyLog.verifyInclusion(
                        TransparencyLog.unhex(Json.string(v, "leaf_hash", "")), Json.number(v, "index", 0L),
                        Json.number(v, "tree_size", 0L), TransparencyLog.decodeHashes(strings(v, "audit_path")),
                        TransparencyLog.unhex(Json.string(v, "root_hash", ""))))));
    }

    @TestFactory
    Stream<DynamicTest> consistencyProofs() throws Exception {
        return group("consistency").stream().map(v -> DynamicTest.dynamicTest(Json.string(v, "name", "?"), () ->
                expect(v, () -> TransparencyLog.verifyConsistency(
                        Json.number(v, "first_size", 0L), Json.number(v, "second_size", 0L),
                        TransparencyLog.unhex(Json.string(v, "first_root", "")),
                        TransparencyLog.unhex(Json.string(v, "second_root", "")),
                        TransparencyLog.decodeHashes(strings(v, "proof"))))));
    }

    @Test
    void receiptLeafHashes() throws Exception {
        for (Map<String, Object> r : group("receipts")) {
            PQCReceipt pqc = PQCReceipt.fromJson(Json.object(r, "pqc"));
            assertEquals(Json.string(r, "leaf_hash", ""), TransparencyLog.hex(TransparencyLog.receiptLeafHash(pqc)));
        }
    }

    /**
     * Signs on a running gateway, then proves the receipt is in its tenant's
     * log, checking the tree head offline. Set QIDS_TEST_GATEWAY_URL and
     * QIDS_TEST_API_KEY to run it.
     */
    @Test
    void inclusionAgainstRealGateway() throws Exception {
        String url = System.getenv("QIDS_TEST_GATEWAY_URL");
        String apiKey = System.getenv("QIDS_TEST_API_KEY");
        assumeTrue(url != null && apiKey != null, "no gateway configured");

        SignResult sig = new QIDSClient(url, "SAE_Alice", apiKey)
                .sign("java-tlog-" + System.nanoTime(), "a document for the log".getBytes(StandardCharsets.UTF_8),
                        List.of("SAE_Bob"));
        PQCReceipt pqc = sig.getPqc();
        String tenant = Json.string(Json.parseObject(new String(
                Base64.getDecoder().decode(pqc.getStatement()), StandardCharsets.UTF_8)), "tenant_id", "");
        QIDSClient reader = new QIDSClient(url, "monitor", (String) null);
        String pem = reader.getPqcKeys(tenant).get(0).getPublicKeyPem();
        TransparencyLog.TreeHeadClaims head = TransparencyLog.verifyTreeHead(reader.getTreeHead(tenant), pem, tenant);
        byte[] leaf = TransparencyLog.receiptLeafHash(pqc);
        TransparencyLog.InclusionProof proof = reader.getInclusionProof(tenant, leaf, head.getTreeSize());
        TransparencyLog.verifyInclusion(leaf, proof.getIndex(), head.getTreeSize(),
                TransparencyLog.decodeHashes(proof.getAuditPath()), TransparencyLog.unhex(head.getRootHash()));
    }
}
