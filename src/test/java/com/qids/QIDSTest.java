package com.qids;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Primitive tests. These were a main() method before, so `gradle test` found
 * no tests and they never ran in any build; the checks are unchanged.
 */
class QIDSTest {

    @Test
    void constantTimePrimitives() {
        byte[] a = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 1, 2, 3, 4};
        byte[] b = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 1, 2, 3, 4};
        byte[] c = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 1, 2, 3, 5}; // 1 bit flip

        assertTrue(ConstantTime.ctEqual(a, b));
        assertFalse(ConstantTime.ctEqual(a, c));
        assertEquals(0L, ConstantTime.ctDistance(a, b));
        assertEquals(1L, ConstantTime.ctDistance(a, c));
        assertTrue(ConstantTime.ctThreshold(4, 5));
        assertTrue(ConstantTime.ctThreshold(5, 5));
        assertFalse(ConstantTime.ctThreshold(6, 5));
    }

    @Test
    void toeplitzHashIsDeterministicAndInputSensitive() {
        byte[] msg1 = "FINANCIAL_TRANSACTION_ORDER_2026".getBytes(StandardCharsets.UTF_8);
        byte[] msg2 = "FINANCIAL_TRANSACTION_ORDER_2027".getBytes(StandardCharsets.UTF_8);
        long polyLo = 0x1BL; // x^64 + x^4 + x^3 + x + 1
        long seed = 0xCAFEBABE12345678L;

        long h1 = ToeplitzHash.hash64(msg1, polyLo, seed);
        assertEquals(h1, ToeplitzHash.hash64(msg1, polyLo, seed));
        assertNotEquals(0L, h1);
        assertNotEquals(h1, ToeplitzHash.hash64(msg2, polyLo, seed));
    }

    @Test
    void waldSprtLifecycle() {
        WaldSPRT detector = new WaldSPRT(0.02, 0.25, 1e-4, 1e-4);
        boolean[] attackStream = {
            true, false, false, false, true, false, false, false,
            true, false, false, false, true, false, false, false,
            true, false, false, false, true, false, false, false,
        };
        assertEquals(WaldSPRT.State.ACCEPT_H1, detector.feed(attackStream));
        assertTrue(detector.getLLR() > 0.0);

        detector.reset();
        assertEquals(0.0, detector.getLLR());
        assertEquals(WaldSPRT.State.CONTINUE, detector.getState());
        assertEquals(WaldSPRT.State.ACCEPT_H0, detector.feed(new boolean[40]));
    }

    @Test
    void etsiKeyBitRepresentation() {
        ETSIKey key = new ETSIKey("key-001", new byte[]{(byte) 0b10110001, (byte) 0b01001110}, 16);
        List<Integer> bits = key.toBitList();
        assertEquals(16, bits.size());
        assertEquals(List.of(1, 0, 1, 1), bits.subList(0, 4));
    }

    @Test
    void localTagComputeAndVerify() {
        QIDSClient client = new QIDSClient("http://localhost:8080", "node-alpha", "sk_test_unused");
        byte[] payload = "AUTHENTICATED_TRANSACTION_PAYLOAD".getBytes(StandardCharsets.UTF_8);
        long polyLo = 0x1BL;
        long seed = 0x123456789ABCDEF0L;

        long tag = client.computeTag(payload, polyLo, seed);
        assertTrue(client.verifyTag(payload, tag, polyLo, seed));
        assertFalse(client.verifyTag(payload, tag ^ 0x01L, polyLo, seed));
    }
}
