package com.qids;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Offline ML-DSA receipt verification against src/test/resources/pqc_vectors.json:
 * receipts signed by a real gateway (ML-DSA-44, -65, -87) and statements no
 * honest gateway signs, each with the outcome to reach. The QIDS repository
 * generates them (tests/vectors/make_pqc_vectors.py) and holds its Python
 * verifier to the same outcomes.
 */
class PQCVerifierTest {

    private static Map<String, Object> vectors() throws Exception {
        try (InputStream in = PQCVerifierTest.class.getResourceAsStream("/pqc_vectors.json")) {
            assertNotNull(in, "pqc_vectors.json missing");
            return Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> vectorList() throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object v : Json.array(vectors(), "vectors")) out.add((Map<String, Object>) v);
        return out;
    }

    @TestFactory
    Stream<DynamicTest> everyVectorReachesItsOutcome() throws Exception {
        List<Map<String, Object>> list = vectorList();
        assertTrue(list.size() >= 30, "only " + list.size() + " vectors");
        return list.stream().map(v -> DynamicTest.dynamicTest(Json.string(v, "name", "?"), () -> {
            byte[] payload = Base64.getDecoder().decode(Json.string(v, "payload_b64", ""));
            PQCReceipt pqc = PQCReceipt.fromJson(Json.object(v, "pqc"));
            String pem = Json.string(v, "public_key_pem", "");
            String tenant = Json.string(v, "tenant_id", null);
            if ("valid".equals(v.get("expect"))) {
                PQCClaims claims = PQCVerifier.verifyPqcReceipt(payload, pqc, pem, tenant);
                assertEquals(Json.object(v, "claims"), claims.asMap());
                assertArrayEquals(Base64.getDecoder().decode(pqc.getStatement()), claims.getStatement());
                assertEquals(pqc.getAlgorithm(), claims.getAlgorithm());
            } else {
                QIDSVerificationException e = assertThrows(QIDSVerificationException.class,
                        () -> PQCVerifier.verifyPqcReceipt(payload, pqc, pem, tenant));
                assertEquals(v.get("reason"), e.getReason().code(), e.getMessage());
            }
        }));
    }

    @Test
    void vectorsCoverEveryReasonAndParameterSet() throws Exception {
        Set<String> reasons = new HashSet<>();
        Set<String> algorithms = new HashSet<>();
        for (Map<String, Object> v : vectorList()) {
            if ("valid".equals(v.get("expect"))) algorithms.add(Json.string(Json.object(v, "pqc"), "algorithm", ""));
            else reasons.add(Json.string(v, "reason", ""));
        }
        Set<String> all = new HashSet<>();
        for (QIDSVerificationException.Reason r : EnumSet.allOf(QIDSVerificationException.Reason.class)) {
            all.add(r.code());
        }
        assertEquals(all, reasons);
        assertEquals(Set.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"), algorithms);
    }

    /** The gateway's signature verifies only under the qids-receipt-v1 context. */
    @Test
    void gatewaySignatureNeedsTheContext() throws Exception {
        Map<String, Object> all = vectors();
        assertEquals(PQCVerifier.CONTEXT, all.get("context"));
        Map<String, Object> check = Json.object(all, "context_check");
        PQCVerifier.MLDSAKey key = PQCVerifier.parsePublicKey(Json.string(check, "public_key_pem", ""));
        assertEquals("ML-DSA-65", key.algorithm);
        Map<String, Object> pqc = Json.object(check, "pqc");
        byte[] statement = Base64.getDecoder().decode(Json.string(pqc, "statement", ""));
        byte[] signature = Base64.getDecoder().decode(Json.string(pqc, "signature", ""));
        assertFalse(PQCVerifier.verifySignature(key.parameters, statement, signature, new byte[0]),
                "the gateway's signature verified with no context");
        assertTrue(PQCVerifier.verifySignature(key.parameters, statement, signature,
                PQCVerifier.CONTEXT.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void getPqcKeysNeedsNoApiKeyAndEscapesTheTenant() throws Exception {
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/pqc/keys/", exchange -> {
            path.set(exchange.getRequestURI().getRawPath());
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            boolean missing = exchange.getRequestURI().getRawPath().endsWith("/nobody");
            byte[] resp = (missing
                    ? "{\"error\":\"No signing keys for this tenant\"}"
                    : "{\"tenant_id\":\"t/1\",\"context\":\"qids-receipt-v1\",\"keys\":["
                    + "{\"key_id\":\"k2\",\"algorithm\":\"ML-DSA-65\",\"status\":\"active\",\"public_key_pem\":\"PEM2\","
                    + "\"created_at\":2.5,\"retired_at\":null},"
                    + "{\"key_id\":\"k1\",\"algorithm\":\"ML-DSA-65\",\"status\":\"retired\",\"public_key_pem\":\"PEM1\","
                    + "\"created_at\":1,\"retired_at\":2.5}]}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(missing ? 404 : 200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            List<PQCPublicKey> keys = new QIDSClient(url, "verifier", (String) null).getPqcKeys("t/1");
            assertEquals("/api/v1/pqc/keys/t%2F1", path.get());
            assertNull(auth.get());
            assertEquals(2, keys.size());
            assertEquals("active", keys.get(0).getStatus());
            assertEquals("PEM2", keys.get(0).getPublicKeyPem());
            assertNull(keys.get(0).getRetiredAt());
            assertEquals(2.5, keys.get(1).getRetiredAt());

            QIDSException e = assertThrows(QIDSException.class,
                    () -> new QIDSClient(url, "verifier", "sk_test_x").getPqcKeys("nobody"));
            assertEquals(404, e.getStatusCode());
            assertEquals("Bearer sk_test_x", auth.get());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void signResultCarriesThePqcReceipt() throws Exception {
        SignResult res = QIDSClient.parseSignResult("{\"document_id\":\"d1\",\"signature_tags\":[],"
                + "\"pqc\":{\"algorithm\":\"ML-DSA-65\",\"key_id\":\"abc\",\"statement\":\"e30=\",\"signature\":\"AAAA\"}}",
                "d1");
        assertEquals(new PQCReceipt("ML-DSA-65", "abc", "e30=", "AAAA"), res.getPqc());
        assertNull(QIDSClient.parseSignResult("{\"document_id\":\"d1\"}", "d1").getPqc());
    }

    /**
     * Sign on a running gateway, fetch the tenant's key once, verify offline.
     * Set QIDS_TEST_GATEWAY_URL and QIDS_TEST_API_KEY to run it.
     */
    @Test
    void roundTripAgainstRealGateway() throws Exception {
        String url = System.getenv("QIDS_TEST_GATEWAY_URL");
        String apiKey = System.getenv("QIDS_TEST_API_KEY");
        assumeTrue(url != null && apiKey != null, "no gateway configured");

        byte[] doc = "PAY ACME 12,000.00 USD é".getBytes(StandardCharsets.UTF_8);
        String docId = "java-pqc-" + System.nanoTime();
        SignResult sig = new QIDSClient(url, "SAE_Alice", apiKey).sign(docId, doc, List.of("SAE_Bob"));
        PQCReceipt pqc = sig.getPqc();
        assertNotNull(pqc, "the gateway returned no pqc receipt");

        // A test may read the tenant from the statement; a real verifier knows
        // whose receipt it expects and pins that tenant's key.
        String tenant = Json.string(Json.parseObject(new String(
                Base64.getDecoder().decode(pqc.getStatement()), StandardCharsets.UTF_8)), "tenant_id", "");
        String pem = null;
        for (PQCPublicKey k : new QIDSClient(url, "verifier", (String) null).getPqcKeys(tenant)) {
            if (k.getKeyId().equals(pqc.getKeyId())) pem = k.getPublicKeyPem();
        }
        assertNotNull(pem, "the receipt's key is not among the tenant's published keys");

        PQCClaims claims = PQCVerifier.verifyPqcReceipt(doc, pqc, pem, tenant);
        assertEquals(docId, claims.getDocumentId());
        assertEquals(sig.getDocumentHash(), claims.getDocumentHash());
        assertEquals(List.of("SAE_Bob"), claims.getRecipients());

        byte[] other = doc.clone();
        other[0] ^= 1;
        String verifiedPem = pem;
        QIDSVerificationException e = assertThrows(QIDSVerificationException.class,
                () -> PQCVerifier.verifyPqcReceipt(other, pqc, verifiedPem, null));
        assertEquals(QIDSVerificationException.Reason.DOCUMENT_MISMATCH, e.getReason());
    }
}
