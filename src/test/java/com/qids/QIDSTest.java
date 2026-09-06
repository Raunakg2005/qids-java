package com.qids;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Comprehensive Verification Test Suite for QIDS Java SDK.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class QIDSTest {

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null && actual == null) return;
        if (expected != null && expected.equals(actual)) return;
        throw new AssertionError(message + " - Expected: " + expected + ", Actual: " + actual);
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    public static void testConstantTime() {
        System.out.println("[*] Testing Java Constant-Time Primitives...");

        byte[] a = new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF, 1, 2, 3, 4};
        byte[] b = new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF, 1, 2, 3, 4};
        byte[] c = new byte[]{(byte)0xDE, (byte)0xAD, (byte)0xBE, (byte)0xEF, 1, 2, 3, 5}; // 1 bit flip

        assertTrue(ConstantTime.ctEqual(a, b), "Equal arrays should return true");
        assertFalse(ConstantTime.ctEqual(a, c), "Unequal arrays should return false");

        assertEquals(0L, ConstantTime.ctDistance(a, b), "Distance between identical arrays should be 0");
        assertEquals(1L, ConstantTime.ctDistance(a, c), "Distance between flipped arrays should be 1");

        assertTrue(ConstantTime.ctThreshold(4, 5), "Observed 4 <= 5 should be true");
        assertTrue(ConstantTime.ctThreshold(5, 5), "Observed 5 <= 5 should be true");
        assertFalse(ConstantTime.ctThreshold(6, 5), "Observed 6 <= 5 should be false");

        System.out.println("    -> Constant-Time Primitives PASSED.");
    }

    public static void testToeplitzHash() {
        System.out.println("[*] Testing Java 64-bit Toeplitz LFSR Universal Hashing...");

        byte[] msg1 = "FINANCIAL_TRANSACTION_ORDER_2026".getBytes(StandardCharsets.UTF_8);
        byte[] msg2 = "FINANCIAL_TRANSACTION_ORDER_2027".getBytes(StandardCharsets.UTF_8);
        long polyLo = 0x1BL; // x^64 + x^4 + x^3 + x + 1
        long seed = 0xCAFEBABE12345678L;

        long h1 = ToeplitzHash.hash64(msg1, polyLo, seed);
        long h2 = ToeplitzHash.hash64(msg1, polyLo, seed);
        long hAlt = ToeplitzHash.hash64(msg2, polyLo, seed);

        assertEquals(h1, h2, "Toeplitz hash must be deterministic");
        assertTrue(h1 != 0, "Toeplitz hash should be non-zero");
        assertTrue(h1 != hAlt, "Toeplitz hash should produce different digests for different inputs");

        System.out.printf("    -> Toeplitz Hash PASSED (Digest: 0x%016X).\n", h1);
    }

    public static void testWaldSPRT() {
        System.out.println("[*] Testing Java Wald SPRT Physical-Layer Threat Detector...");

        // p0 = 0.02 (honest), p1 = 0.25 (intercept-resend), alpha = 1e-4, beta = 1e-4
        WaldSPRT detector = new WaldSPRT(0.02, 0.25, 1e-4, 1e-4);

        // Feed attack stream (25% errors)
        boolean[] attackStream = {
            true, false, false, false,
            true, false, false, false,
            true, false, false, false,
            true, false, false, false,
            true, false, false, false,
            true, false, false, false
        };

        WaldSPRT.State state = detector.feed(attackStream);
        assertEquals(WaldSPRT.State.ACCEPT_H1, state, "SPRT detector must trigger ACCEPT_H1 on attack stream");
        assertTrue(detector.getLLR() > 0.0, "LLR must be positive under attack");

        // Test Reset and honest sequence (0% errors)
        detector.reset();
        assertEquals(0.0, detector.getLLR(), "LLR should reset to 0");
        assertEquals(WaldSPRT.State.CONTINUE, detector.getState(), "State should reset to CONTINUE");

        boolean[] cleanStream = new boolean[40]; // all false
        state = detector.feed(cleanStream);
        assertEquals(WaldSPRT.State.ACCEPT_H0, state, "SPRT detector must accept honest link on clean stream");

        System.out.println("    -> Wald SPRT Detector Lifecycle PASSED.");
    }

    public static void testETSIKey() {
        System.out.println("[*] Testing Java ETSI Key Bit Representation...");

        byte[] keyBytes = new byte[]{(byte) 0b10110001, (byte) 0b01001110};
        ETSIKey key = new ETSIKey("key-001", keyBytes, 16);

        List<Integer> bits = key.toBitList();
        assertEquals(16, bits.size(), "Bit list must have exactly 16 bits");
        assertEquals(1, bits.get(0), "First bit should be 1");
        assertEquals(0, bits.get(1), "Second bit should be 0");
        assertEquals(1, bits.get(2), "Third bit should be 1");
        assertEquals(1, bits.get(3), "Fourth bit should be 1");

        System.out.println("    -> ETSI Key Representation PASSED.");
    }

    public static void testQIDSClientLocal() {
        System.out.println("[*] Testing QIDSClient Local Tag Compute and Verify...");

        QIDSClient client = new QIDSClient("http://localhost:8080", "node-alpha");
        byte[] payload = "AUTHENTICATED_TRANSACTION_PAYLOAD".getBytes(StandardCharsets.UTF_8);
        long polyLo = 0x1BL;
        long seed = 0x123456789ABCDEF0L;

        long tag = client.computeTag(payload, polyLo, seed);
        assertTrue(client.verifyTag(payload, tag, polyLo, seed), "Tag verification should pass with authentic tag");

        long tamperedTag = tag ^ 0x01L;
        assertFalse(client.verifyTag(payload, tamperedTag, polyLo, seed), "Tag verification must fail with tampered tag");

        System.out.println("    -> QIDSClient Local Verification PASSED.");
    }

    public static void main(String[] args) {
        System.out.println("=====================================================");
        System.out.println("  QIDS Java SDK v1.3.2 Verification Test Suite       ");
        System.out.println("=====================================================");

        testConstantTime();
        testToeplitzHash();
        testWaldSPRT();
        testETSIKey();
        testQIDSClientLocal();

        System.out.println("\n>>> ALL QIDS JAVA SDK TESTS PASSED SUCCESSFULLY <<<");
    }
}
