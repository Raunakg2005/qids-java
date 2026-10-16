package com.qids;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Request timeouts, typed gateway errors, verify fields and strict ETSI keys. */
class ClientHardeningTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    /** A server answering every request with this status, headers and body after a delay. */
    private String serve(int status, Map<String, String> headers, String body, long delayMs,
                         AtomicReference<String> request) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/", exchange -> {
            if (request != null) {
                request.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            }
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            headers.forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
            byte[] resp = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            } catch (IOException ignored) {
                // The client gave up (timeout test).
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void gatewayCallsHonourTheTimeout() throws Exception {
        String url = serve(200, Map.of(), "{\"document_id\":\"d\",\"signature_tags\":[]}", 5000, null);
        QIDSClient client = new QIDSClient(url, "SAE_Alice", "sk_test_k", Duration.ofMillis(300));
        long start = System.nanoTime();
        assertThrows(HttpTimeoutException.class, () -> client.sign("d", new byte[] {1}, List.of("SAE_Bob")));
        assertThrows(HttpTimeoutException.class, () -> client.verify("d", new byte[] {1}, "ab", "k1"));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsedMs < 3000, "two 300 ms timeouts took " + elapsedMs + " ms");
    }

    @Test
    void etsiCallsHonourTheTimeout() throws Exception {
        String url = serve(200, Map.of(), "{\"keys\":[]}", 5000, null);
        ETSI014Client etsi = new ETSI014Client(url, "SAE_Alice", "SAE_Bob", Duration.ofMillis(300));
        long start = System.nanoTime();
        assertThrows(HttpTimeoutException.class, etsi::getStatus);
        assertThrows(HttpTimeoutException.class, () -> etsi.getEncKeys(1, 384));
        assertThrows(HttpTimeoutException.class, () -> etsi.getDecKeys(List.of("k1")));
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;
        assertTrue(elapsedMs < 4000, "three 300 ms timeouts took " + elapsedMs + " ms");
    }

    @Test
    void rateLimitIsTypedWithRetryAfter() throws Exception {
        String url = serve(429, Map.of(),
                "{\"error\":\"Rate limit exceeded\",\"limit_rpm\":60,\"retry_after_seconds\":60}", 0, null);
        QIDSException.RateLimited e = assertThrows(QIDSException.RateLimited.class,
                () -> new QIDSClient(url, "SAE_Alice", "sk_test_k").sign("d", new byte[] {1}, List.of("SAE_Bob")));
        assertEquals(429, e.getStatusCode());
        assertEquals("Rate limit exceeded", e.getError());
        assertEquals(Duration.ofSeconds(60), e.getRetryAfter().orElseThrow());
    }

    @Test
    void retryAfterHeaderIsUsedWhenTheBodyHasNone() throws Exception {
        String url = serve(429, Map.of("Retry-After", "7"), "{\"error\":\"Too many links\"}", 0, null);
        QIDSException.RateLimited e = assertThrows(QIDSException.RateLimited.class,
                () -> new QIDSClient(url, "SAE_Alice", "sk_test_k").verify("d", new byte[] {1}, "ab", "k1"));
        assertEquals(Duration.ofSeconds(7), e.getRetryAfter().orElseThrow());
    }

    @Test
    void unauthorizedAndForbiddenAreDistinct() throws Exception {
        String url = serve(401, Map.of(), "{\"error\":\"Unauthorized\",\"message\":\"Valid API key required.\"}", 0, null);
        QIDSException.Unauthorized e401 = assertThrows(QIDSException.Unauthorized.class,
                () -> new QIDSClient(url, "SAE_Alice", "sk_test_bad").sign("d", new byte[] {1}, List.of()));
        assertTrue(e401.getMessage().contains("Valid API key required."), e401.getMessage());
        server.stop(0);

        String url2 = serve(403, Map.of(),
                "{\"error\":\"Forbidden\",\"message\":\"Role 'auditor' lacks the 'sign' permission.\","
                        + "\"required_permission\":\"sign\"}", 0, null);
        QIDSException.Forbidden e403 = assertThrows(QIDSException.Forbidden.class,
                () -> new QIDSClient(url2, "SAE_Alice", "sk_test_k").sign("d", new byte[] {1}, List.of()));
        assertEquals("sign", e403.getRequiredPermission());
        assertFalse(e403.getRetryAfter().isPresent());
    }

    @Test
    void verifyKeepsRatesThreatConfidenceAndEvidence() throws Exception {
        VerifyResult res = QIDSClient.parseVerifyResult("{\"document_id\":\"d\",\"status\":\"REJECTED\","
                + "\"is_valid\":false,\"observed_error_rate\":1.0,\"threshold_error_rate\":0.1111,"
                + "\"reason\":\"tag_mismatch\",\"threat\":\"forgery\",\"confidence\":0.75,"
                + "\"evidence\":{\"submitted_tag\":\"ab\"}}", "d");
        assertEquals(1.0, res.getObservedErrorRate());
        assertEquals(0.1111, res.getThresholdErrorRate());
        assertEquals("forgery", res.getThreat());
        assertEquals(0.75, res.getConfidence());
        assertEquals("ab", res.getEvidence().get("submitted_tag"));
    }

    @Test
    void verifyWithATagSendsItsRecipient() throws Exception {
        AtomicReference<String> request = new AtomicReference<>();
        String url = serve(200, Map.of(), "{\"status\":\"ACCEPTED\",\"is_valid\":true}", 0, request);
        new QIDSClient(url, "SAE_Alice", "sk_test_k")
                .verify("d", new byte[] {1}, new SignatureTag("SAE_Carol", "ab", 128, "k1"));
        Map<String, Object> sent = Json.parseObject(request.get());
        assertEquals("SAE_Carol", sent.get("recipient_sae_id"));
        assertEquals("ab", sent.get("hash_tag"));
        assertEquals("k1", sent.get("key_id"));
    }

    private static String keys(String key) {
        return "{\"keys\":[{\"key_ID\":\"k1\",\"key\":\"" + key + "\"}]}";
    }

    @Test
    void encKeysRejectWrongSizeAndUndecodableKeys() throws Exception {
        String key48 = Base64.getEncoder().encodeToString(new byte[48]);
        List<ETSIKey> ok = ETSI014Client.parseKeys(keys(key48), 384);
        assertEquals(384, ok.get(0).getSizeBits());

        String key32 = Base64.getEncoder().encodeToString(new byte[32]);
        assertThrows(IOException.class, () -> ETSI014Client.parseKeys(keys(key32), 384),
                "a 256-bit key was accepted as 384 bits");
        assertThrows(IOException.class, () -> ETSI014Client.parseKeys(keys("!!not-a-key!!"), 384));
        assertThrows(IOException.class, () -> ETSI014Client.parseKeys(keys("!!not-a-key!!"), 0));
        assertThrows(IOException.class, () -> ETSI014Client.parseKeys(keys(""), 0));
    }
}
