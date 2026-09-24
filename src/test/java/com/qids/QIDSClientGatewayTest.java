package com.qids;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** Gateway client tests: what goes on the wire, and the real round trip. */
class QIDSClientGatewayTest {

    /** Not valid UTF-8: new String(this, UTF_8) maps 0xff to U+FFFD. */
    private static final byte[] BINARY_DOC = {(byte) 0xff, 'P', 'A', 'Y', ' ', '1', '0', '0', 0, 1};

    @Test
    void signSendsBearerKeyAndExactPayloadBytes() throws Exception {
        AtomicReference<String> auth = new AtomicReference<>();
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v1/sign", exchange -> {
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] resp = "{\"document_id\":\"d\",\"signature_tags\":[]}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, resp.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(resp);
            }
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            new QIDSClient(url, "SAE_Alice", "sk_test_abc").sign("id\twith \"tab\"", BINARY_DOC, List.of("SAE_Bob"));
        } finally {
            server.stop(0);
        }

        assertEquals("Bearer sk_test_abc", auth.get());
        assertFalse(body.get().contains("\"payload\":"), "must not send lossy text 'payload'");
        Matcher m = Pattern.compile("\"payload_b64\":\"([^\"]*)\"").matcher(body.get());
        assertTrue(m.find(), "payload_b64 missing from " + body.get());
        assertArrayEquals(BINARY_DOC, Base64.getDecoder().decode(m.group(1)));
        assertTrue(body.get().contains("id\\u0009with \\\"tab\\\""), "control characters must be JSON-escaped");
    }

    /** Set QIDS_TEST_GATEWAY_URL and QIDS_TEST_API_KEY to run against a real gateway. */
    @Test
    void differentBinaryDocumentDoesNotVerifyAgainstRealGateway() throws Exception {
        String url = System.getenv("QIDS_TEST_GATEWAY_URL");
        String key = System.getenv("QIDS_TEST_API_KEY");
        assumeTrue(url != null && key != null, "no gateway configured");

        QIDSClient client = new QIDSClient(url, "SAE_Alice", key);
        byte[] other = BINARY_DOC.clone();
        other[0] = (byte) 0xfe;
        String docId = "java-bin-" + System.nanoTime();

        SignResult sig = client.sign(docId, BINARY_DOC, List.of("SAE_Bob"));
        SignatureTag tag = sig.getSignatureTags().get(0);
        VerifyResult genuine = client.verify(docId, BINARY_DOC, tag.getHashTag(), tag.getKeyId());
        VerifyResult substituted = client.verify(docId, other, tag.getHashTag(), tag.getKeyId());

        assertTrue(genuine.isValid());
        assertEquals("ACCEPTED", genuine.getStatus());
        assertFalse(substituted.isValid(), "a different binary document verified with the same signature");
        assertEquals("REJECTED", substituted.getStatus());
    }
}
