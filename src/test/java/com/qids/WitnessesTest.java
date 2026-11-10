package com.qids;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Witness co-signatures checked offline against src/test/resources/witness_vectors.json:
 * a real gateway's GET /api/v1/tlog/&lt;tenant&gt;/cosigned, co-signed by real
 * qids.witness witnesses, and edits of it, each with the outcome to reach. The
 * QIDS repository generates them (tests/vectors/make_witness_vectors.py) and
 * holds its Python verifier and the TypeScript SDK to the same outcomes.
 */
class WitnessesTest {

    private static Map<String, Object> vectors() throws Exception {
        try (InputStream in = WitnessesTest.class.getResourceAsStream("/witness_vectors.json")) {
            assertNotNull(in, "witness_vectors.json missing");
            return Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> cases() throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object v : Json.array(vectors(), "cosigned")) out.add((Map<String, Object>) v);
        return out;
    }

    private static String key(String name) throws Exception {
        return Json.string(Json.object(vectors(), "keys"), name, null);
    }

    private static List<String> keys(Map<String, Object> v) throws Exception {
        List<String> out = new ArrayList<>();
        for (Object k : Json.array(v, "trusted")) out.add(key((String) k));
        return out;
    }

    private static String reasonOf(Executable check) {
        QIDSVerificationException e = assertThrows(QIDSVerificationException.class, check::run);
        return e.getReason().code();
    }

    @FunctionalInterface
    private interface Executable {
        void run() throws Exception;
    }

    @Test
    void contextMatchesTheVectors() throws Exception {
        assertEquals(Witnesses.CONTEXT, vectors().get("witness_context"));
    }

    @TestFactory
    Stream<DynamicTest> everyVectorReachesItsOutcome() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (Map<String, Object> v : cases()) {
            tests.add(DynamicTest.dynamicTest((String) v.get("name"), () -> {
                Witnesses.CosignedTreeHeads cosigned = Witnesses.CosignedTreeHeads.fromJson(Json.object(v, "cosigned"));
                String tenant = (String) v.get("tenant_id");
                int quorum = (int) Json.number(v, "quorum", 0);
                if ("valid".equals(v.get("expect"))) {
                    Witnesses.CosignedTreeHeadClaims got = Witnesses.verifyCosignedTreeHead(
                            cosigned, key((String) v.get("log_key")), keys(v), quorum, tenant);
                    assertEquals(Json.number(v, "tree_size", -1), got.getTreeSize());
                    assertEquals(Json.array(v, "witnesses"), new ArrayList<Object>(got.getWitnesses()));
                    assertEquals(Json.number(v, "cosigned_at_ms", -1), got.getCosignedAtMs());
                    assertEquals("ML-DSA-65", got.getHead().getAlgorithm());
                } else {
                    assertEquals(v.get("reason"), reasonOf(() -> Witnesses.verifyCosignedTreeHead(
                            cosigned, key((String) v.get("log_key")), keys(v), quorum, tenant)));
                }
            }));
        }
        return tests.stream();
    }

    @Test
    void theVectorsCoverEveryReasonAndABusyLog() throws Exception {
        Set<Object> reasons = new TreeSet<>();
        Set<Long> sizes = new TreeSet<>();
        for (Map<String, Object> v : cases()) {
            if ("valid".equals(v.get("expect"))) sizes.add(Json.number(v, "tree_size", -1));
            else reasons.add(v.get("reason"));
        }
        assertEquals(Set.of("invalid_key", "quorum_not_met", "witness_is_log_key"), reasons);
        assertEquals(Set.of(3L, 5L), sizes);
    }

    /** The smaller head of the vectors, co-signed by all three witnesses. */
    private static Witnesses.CosignedHead fullHead() throws Exception {
        for (Map<String, Object> v : cases()) {
            if ("a quorum of 3".equals(v.get("name"))) {
                return Witnesses.CosignedTreeHeads.fromJson(Json.object(v, "cosigned")).getHeads().get(1);
            }
        }
        throw new AssertionError("no vector named 'a quorum of 3'");
    }

    private static Witnesses.Cosignature cosigBy(Witnesses.CosignedHead head, String name) throws Exception {
        String kid = Json.string(Json.object(vectors(), "witness_kids"), name, null);
        for (Witnesses.Cosignature c : head.getCosignatures()) {
            if (kid.equals(c.getWitness())) return c;
        }
        throw new AssertionError("no co-signature by " + name);
    }

    @Test
    void oneCosignatureVerifiesAndOthersAreRefused() throws Exception {
        Witnesses.CosignedHead head = fullHead();
        TransparencyLog.TreeHeadClaims claims = TransparencyLog.verifyTreeHead(head.getSth(), key("log_a"), null);
        Witnesses.CosignatureClaims got = Witnesses.verifyCosignature(cosigBy(head, "w2"), key("w2"), claims);
        assertEquals(cosigBy(head, "w2").getWitness(), got.getWitness());
        assertEquals(claims.getTreeSize(), got.getTreeSize());
        assertEquals(claims.getRootHash(), got.getRootHash());
        assertEquals(claims.getKeyId(), got.getLogKeyId());
        assertTrue(got.getCosignedAtMs() > 0);

        assertEquals("bad_cosignature",
                reasonOf(() -> Witnesses.verifyCosignature(cosigBy(head, "w2"), key("w3"), claims)));
        Witnesses.Cosignature garbled = new Witnesses.Cosignature(cosigBy(head, "w2").getWitness(), "not base64!",
                cosigBy(head, "w2").getSignature());
        assertEquals("bad_cosignature", reasonOf(() -> Witnesses.verifyCosignature(garbled, key("w2"), claims)));
        assertEquals("invalid_key",
                reasonOf(() -> Witnesses.verifyCosignature(cosigBy(head, "w2"), key("ml_dsa_44"), claims)));
        // The same co-signature against another tenant's head: another head, another log key.
        TransparencyLog.TreeHeadClaims otherHead = TransparencyLog.verifyTreeHead(
                tenantBHead(), key("log_b"), null);
        assertEquals("cosignature_mismatch",
                reasonOf(() -> Witnesses.verifyCosignature(cosigBy(head, "w2"), key("w2"), otherHead)));
    }

    private static TransparencyLog.SignedTreeHead tenantBHead() throws Exception {
        for (Map<String, Object> v : cases()) {
            if ("another tenant's head with these co-signatures".equals(v.get("name"))) {
                return Witnesses.CosignedTreeHeads.fromJson(Json.object(v, "cosigned")).getHeads().get(0).getSth();
            }
        }
        throw new AssertionError("no vector with tenant B's head");
    }

    @Test
    void theQuorumMustBeAtLeastOne() throws Exception {
        Witnesses.CosignedTreeHeads cosigned = Witnesses.CosignedTreeHeads.fromJson(Json.object(cases().get(0), "cosigned"));
        for (int q : new int[] {0, -1}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Witnesses.verifyCosignedTreeHead(cosigned, key("log_a"), List.of(key("w1")), q, null));
        }
        assertEquals("quorum_not_met", reasonOf(
                () -> Witnesses.verifyCosignedTreeHead(null, key("log_a"), List.of(key("w1")), 1, null)));
    }

    @Test
    void getCosignedTreeHeadReadsThePublicRouteWithNoApiKey() throws Exception {
        String body = Json.write(Json.object(cases().get(2), "cosigned"));
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            path.set(exchange.getRequestURI().getRawPath());
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        try {
            QIDSClient client = new QIDSClient("http://127.0.0.1:" + server.getAddress().getPort(), "t", "sk_secret");
            Witnesses.CosignedTreeHeads got = client.getCosignedTreeHead("tenant/with slash");
            assertEquals("/api/v1/tlog/tenant%2Fwith%20slash/cosigned", path.get());
            assertNull(auth.get());
            Witnesses.CosignedTreeHeadClaims head = Witnesses.verifyCosignedTreeHead(
                    got, key("log_a"), List.of(key("w1"), key("w2"), key("w3")), 2, null);
            assertEquals(3, head.getTreeSize());
        } finally {
            server.stop(0);
        }
    }
}
