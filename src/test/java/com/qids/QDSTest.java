package com.qids;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** QDS mode: QIDSClient.qdsSign and VerifierNode. */
class QDSTest {

    private static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    @Test
    void theWriterRoundTripsAnEnvelopeExactly() {
        String envelope = "{\"v\":\"qids-qds/1\",\"n\":128,\"timestamp\":1794227156.2199745,\"sig\":\"ab\","
                + "\"holders\":[\"bob\",\"charlie\"],\"holder_tags\":[[\"m1\",\"t1\"],[\"m2\",\"t2\"]],"
                + "\"x\":\"a\\\"b\\\\c\\n\\u0001\",\"t\":true,\"z\":null,\"whole\":1794227156.0}";
        Object parsed = Json.parse(envelope);
        Object again = Json.parse(Json.write(parsed));
        assertEquals(parsed, again);
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) again;
        assertEquals(1794227156.2199745, (Double) m.get("timestamp"), 0.0);
        assertEquals(128L, m.get("n"));
    }

    @Test
    void qdsSignSendsHoldersAndMapsTheAnswer() throws Exception {
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/qds/sign", ex -> {
            body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            reply(ex, 200, "{\"document_id\":\"d1\",\"sig_id\":\"s1\",\"envelope\":{\"v\":\"qids-qds/1\"},"
                    + "\"delivered\":{\"bob\":\"stored\"},\"entropy_source\":[\"ETSI-GS-QKD-014-MOCK\"],"
                    + "\"qkd_backed\":false,\"pqc\":{\"algorithm\":\"ML-DSA-65\",\"key_id\":\"k\","
                    + "\"statement\":\"c3Q=\",\"signature\":\"c2c=\"}}");
        });
        server.start();
        try {
            QIDSClient c = new QIDSClient("http://127.0.0.1:" + server.getAddress().getPort(), "app", "sk_test_x");
            byte[] doc = {(byte) 0xff, 'P', 0};
            QDSSignResult r = c.qdsSign("d1", doc, List.of("bob", "charlie"));
            Map<String, Object> sent = Json.parseObject(body.get());
            assertEquals(Base64.getEncoder().encodeToString(doc), sent.get("payload_b64"));
            assertEquals(List.of("bob", "charlie"), sent.get("holders"));
            assertEquals("s1", r.getSigId());
            assertEquals("stored", r.getDelivered().get("bob"));
            assertFalse(r.isQkdBacked());
            assertEquals("k", r.getPqc().getKeyId());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void aNodeDeliversWithoutAndVerifiesWithTheToken() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/qds/signatures", ex -> reply(ex, 200, "{\"stored\":true}"));
        server.createContext("/v1/qds/verify", ex -> {
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            if (!"Bearer op".equals(auth)) {
                reply(ex, 401, "{\"error\":\"token\"}");
                return;
            }
            reply(ex, 200, "{\"holder\":\"bob\",\"sig_id\":\"s1\",\"accepted\":true,\"reason\":\"ok\"}");
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            assertTrue(new VerifierNode(url, null).deliver(new LinkedHashMap<>()));
            assertThrows(IllegalStateException.class, () -> new VerifierNode(url, "").verify(new byte[] {1}, Map.of()));
            assertThrows(QIDSException.Unauthorized.class, () -> new VerifierNode(url, "wrong").verify(new byte[] {1}, Map.of()));
            QDSVerdict v = new VerifierNode(url, "op").verify(new byte[] {1}, Map.of());
            assertTrue(v.isAccepted());
            assertEquals("bob", v.getHolder());
        } finally {
            server.stop(0);
        }
    }

    // -- the end-of-phase audit (gateway audit 2.84) ---------------------------------------

    private static HttpServer stub(int status, String body, boolean stallBody) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, stallBody ? b.length + 100 : b.length);
            OutputStream os = ex.getResponseBody();
            os.write(b);
            os.flush();
            if (stallBody) {
                try {
                    Thread.sleep(20_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            os.close();
        });
        server.start();
        return server;
    }

    private static String url(HttpServer s) {
        return "http://127.0.0.1:" + s.getAddress().getPort();
    }

    @Test
    void aNullOrEmptyDocumentIsRefusedBeforeAnythingIsSent() throws Exception {
        HttpServer server = stub(200, "{}", false);
        try {
            assertThrows(IllegalArgumentException.class, () -> new VerifierNode(url(server), "op").verify(null, Map.of()));
            assertThrows(IllegalArgumentException.class, () -> new VerifierNode(url(server), "op").verify(new byte[0], Map.of()));
            assertThrows(IllegalStateException.class, () -> new VerifierNode(url(server), "   ").verify(new byte[] {1}, Map.of()));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void theTimeoutCoversTheBody() throws Exception {
        HttpServer server = stub(200, "{\"accepted\":true", true);
        try {
            long t = System.nanoTime();
            assertThrows(java.net.http.HttpTimeoutException.class, () ->
                    new VerifierNode(url(server), "op", java.time.Duration.ofSeconds(2)).verify(new byte[] {1}, Map.of()));
            assertTrue((System.nanoTime() - t) / 1e9 < 6, "the call outlived its timeout");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void answersThatAreNotVerdictsAreErrors() throws Exception {
        for (String[] c : new String[][] {{"200", "{\"reason\":\"ok\"}"}, {"200", "{\"accepted\":\"false\"}"},
                {"200", "<html>"}, {"404", "{\"error\":\"Not found\"}"}}) {
            HttpServer server = stub(Integer.parseInt(c[0]), c[1], false);
            try {
                assertThrows(Exception.class, () -> new VerifierNode(url(server), "op").verify(new byte[] {1}, Map.of()),
                        c[0] + " " + c[1]);
            } finally {
                server.stop(0);
            }
        }
        HttpServer refused = stub(400, "{\"stored\":false,\"reason\":\"envelope_unauthentic\"}", false);
        try {
            assertFalse(new VerifierNode(url(refused), null).deliver(new LinkedHashMap<>()));
        } finally {
            refused.stop(0);
        }
        for (String[] c : new String[][] {{"404", "{\"error\":\"Not found\"}"}, {"200", "{\"stored\":false}"}}) {
            HttpServer server = stub(Integer.parseInt(c[0]), c[1], false);
            try {
                assertThrows(Exception.class, () -> new VerifierNode(url(server), null).deliver(new LinkedHashMap<>()));
            } finally {
                server.stop(0);
            }
        }
    }

    /** With QIDS_TEST_QDS_GATEWAY_URL, QIDS_TEST_API_KEY, QIDS_TEST_QDS_NODES and QIDS_TEST_QDS_TOKENS. */
    @Test
    void againstRealGateway() throws Exception {
        String gw = System.getenv("QIDS_TEST_QDS_GATEWAY_URL");
        assumeTrue(gw != null, "set QIDS_TEST_QDS_GATEWAY_URL");
        Map<String, String> nodes = pairs(System.getenv("QIDS_TEST_QDS_NODES"));
        Map<String, String> tokens = pairs(System.getenv("QIDS_TEST_QDS_TOKENS"));
        QIDSClient c = new QIDSClient(gw, "java", System.getenv("QIDS_TEST_API_KEY"));
        byte[] doc = ("java sdk qds " + System.nanoTime()).getBytes(StandardCharsets.UTF_8);
        QDSSignResult r = c.qdsSign("java-" + System.nanoTime(), doc, new ArrayList<>(nodes.keySet()));
        for (Map.Entry<String, String> n : nodes.entrySet()) {
            QDSVerdict v = new VerifierNode(n.getValue(), tokens.get(n.getKey())).verify(doc, r.getEnvelope());
            assertTrue(v.isAccepted(), n.getKey() + ": " + v.getReason());
        }
        String first = nodes.keySet().iterator().next();
        byte[] changed = (new String(doc, StandardCharsets.UTF_8) + "!").getBytes(StandardCharsets.UTF_8);
        assertFalse(new VerifierNode(nodes.get(first), tokens.get(first)).verify(changed, r.getEnvelope()).isAccepted());
    }

    private static Map<String, String> pairs(String v) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String p : (v == null ? "" : v).split(",")) {
            int i = p.indexOf('=');
            if (i > 0) m.put(p.substring(0, i), p.substring(i + 1));
        }
        return m;
    }
}
