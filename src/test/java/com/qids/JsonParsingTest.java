package com.qids;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Responses are parsed as JSON, not matched by regular expressions that
 * required fields in one exact order and nothing else.
 */
class JsonParsingTest {

    @Test
    void parsesEveryJsonType() {
        Map<String, Object> obj = Json.parseObject(
                "{\"s\":\"a\\\"b\\\\c\\u00e9\\n\",\"i\":-42,\"big\":12345678901234567890,"
                        + "\"f\":1.5e2,\"t\":true,\"n\":null,\"a\":[1,{\"x\":[]}],\"o\":{}}");
        assertEquals("a\"b\\c\u00e9\n", obj.get("s"));
        assertEquals(-42L, obj.get("i"));
        assertEquals(1.2345678901234567e19, (Double) obj.get("big"), 1e4);
        assertEquals(150.0, obj.get("f"));
        assertEquals(Boolean.TRUE, obj.get("t"));
        assertTrue(obj.containsKey("n"));
        assertNull(obj.get("n"));
        assertEquals(2, ((List<?>) obj.get("a")).size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "{", "{\"a\":1,}", "[1 2]", "{\"a\":01}", "\"unterminated", "{\"a\":\"x\ny\"}",
            "{\"a\":tru}", "{} {}", "{\"a\":\"\\q\"}"})
    void rejectsInvalidJson(String bad) {
        assertThrows(IllegalArgumentException.class, () -> Json.parse(bad));
    }

    @Test
    void signResultReadsFieldsByNameInAnyOrderWithExtras() throws IOException {
        // Tag fields reordered and an extra field added: the old regex found no tags.
        String body = "{\"status\":\"SIGNED_QUANTUM_SAFE\",\"document_id\":\"doc_server_named\","
                + "\"document_hash\":\"ab12\",\"signed_at_utc_ms\":1758750000123,\"algorithm\":\"QIDS-OTUH-256\","
                + "\"signature_tags\":[{\"key_id\":\"otuh-1\",\"tag_length_bits\":256,\"note\":\"x\","
                + "\"hash_tag\":\"f00d\",\"recipient_sae_id\":\"SAE_Bob\"}],"
                + "\"entropy_source\":[\"ETSI-GS-QKD-014-MOCK\"],\"qkd_backed\":false}";
        SignResult res = QIDSClient.parseSignResult(body, null);

        assertEquals("doc_server_named", res.getDocumentId());   // was the requested id: null
        assertEquals(1758750000123L, res.getSignedAtUtcMs());      // was the local clock
        assertEquals("QIDS-OTUH-256", res.getAlgorithm());
        assertEquals(1, res.getSignatureTags().size());
        SignatureTag tag = res.getSignatureTags().get(0);
        assertEquals("SAE_Bob", tag.getRecipientSaeId());
        assertEquals("f00d", tag.getHashTag());
        assertEquals(256, tag.getTagLengthBits());
        assertEquals("otuh-1", tag.getKeyId());
        assertEquals(Arrays.asList("ETSI-GS-QKD-014-MOCK"), res.getEntropySource());
        assertFalse(res.isQkdBacked());
    }

    @Test
    void onlyATopLevelTrueIsValid() throws IOException {
        // A nested "is_valid":true used to satisfy a substring match.
        VerifyResult nested = QIDSClient.parseVerifyResult(
                "{\"status\":\"REJECTED\",\"evidence\":{\"is_valid\":true},\"is_valid\":false,\"reason\":\"digest_mismatch\"}", "d");
        assertFalse(nested.isValid());
        assertEquals("REJECTED", nested.getStatus());
        assertEquals("digest_mismatch", nested.getReason());

        VerifyResult noStatus = QIDSClient.parseVerifyResult("{\"is_valid\":\"true\"}", "d");
        assertFalse(noStatus.isValid());                           // a string is not a boolean
        assertEquals("UNKNOWN", noStatus.getStatus());

        assertTrue(QIDSClient.parseVerifyResult("{\"status\":\"ACCEPTED\",\"is_valid\":true}", "d").isValid());
    }

    @Test
    void anUnparseableResponseIsAnIOException() {
        assertThrows(IOException.class, () -> QIDSClient.parseSignResult("<html>502 Bad Gateway</html>", "d"));
        assertThrows(IOException.class, () -> QIDSClient.parseVerifyResult("[]", "d"));
    }

    @Test
    void etsiKeysWithExtensionFieldsAndAnyOrderAreParsed() throws IOException {
        // ETSI GS QKD 014 allows key_ID_extension / key_extension and any field
        // order. The old regex returned an empty list for this, silently.
        String body = "{\"keys\":[{\"key\":\"AAEC\",\"key_ID\":\"k-1\",\"key_ID_extension\":{\"v\":1}},"
                + "{\"key_ID\":\"k-2\",\"key\":\"AwQF\",\"key_extension\":null}],"
                + "\"key_container_extension\":{\"qids_mock_kms\":true}}";
        List<ETSIKey> keys = ETSI014Client.parseKeys(body, 0);
        assertEquals(2, keys.size());
        assertEquals("k-1", keys.get(0).getKeyId());
        assertArrayEquals(new byte[] {0, 1, 2}, keys.get(0).getKeyBytes());
        assertEquals(24, keys.get(0).getSizeBits());
        assertEquals("k-2", keys.get(1).getKeyId());
    }

    @Test
    void anEtsiKeyWithoutMaterialIsAnError() {
        assertThrows(IOException.class, () -> ETSI014Client.parseKeys("{\"keys\":[{\"key_ID\":\"k-1\"}]}", 0));
    }
}
