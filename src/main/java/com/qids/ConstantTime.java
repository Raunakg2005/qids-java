package com.qids;

/**
 * Constant-time cryptographic comparison and threshold verification primitives.
 *
 * All operations execute in data-independent time to eliminate microarchitectural
 * cache-timing side channels.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class ConstantTime {

    private ConstantTime() {}

    /**
     * Constant-time byte array equality check.
     */
    public static boolean ctEqual(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    /**
     * Constant-time Hamming distance between two byte buffers.
     * Returns -1 if inputs are null or lengths mismatch.
     */
    public static long ctDistance(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return -1;
        }
        long dist = 0;
        for (int i = 0; i < a.length; i++) {
            int v = (a[i] ^ b[i]) & 0xFF;
            dist += Integer.bitCount(v);
        }
        return dist;
    }

    /**
     * Constant-time threshold verification.
     */
    public static boolean ctThreshold(long observedMismatches, long maxAllowed) {
        return observedMismatches <= maxAllowed;
    }
}
