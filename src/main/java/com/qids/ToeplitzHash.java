package com.qids;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 64-bit Toeplitz LFSR-based Universal Hashing over GF(2^64).
 *
 * Implements Krawczyk's almost-universal hash family evaluated via Horner's rule
 * with injectivity termination bit 0x01.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class ToeplitzHash {

    private static final int[] REVERSE_BYTE_TABLE = new int[256];

    static {
        for (int i = 0; i < 256; i++) {
            int b = i;
            int rev = 0;
            for (int j = 0; j < 8; j++) {
                rev = (rev << 1) | (b & 1);
                b >>>= 1;
            }
            REVERSE_BYTE_TABLE[i] = rev;
        }
    }

    private ToeplitzHash() {}

    /**
     * Carry-less multiplication of two 64-bit polynomials over GF(2).
     * Returns 128-bit product as long[]{hi, lo}.
     */
    public static long[] clmul64(long a, long b) {
        long hi = 0;
        long lo = 0;
        for (int i = 0; i < 64; i++) {
            if (((b >>> i) & 1L) != 0) {
                lo ^= (a << i);
                if (i > 0) {
                    hi ^= (a >>> (64 - i));
                }
            }
        }
        return new long[]{hi, lo};
    }

    /**
     * Reduces 128-bit polynomial (vHi, vLo) modulo a degree-64 polynomial p (x^64 + polyLo).
     */
    public static long polyMod64(long vHi, long vLo, long polyLo) {
        while (vHi != 0) {
            int lz = Long.numberOfLeadingZeros(vHi);
            int deg = 127 - lz;
            int shift = deg - 64;

            if (shift >= 64) {
                int s = shift - 64;
                vHi ^= (1L << s);
            } else if (shift == 0) {
                vHi ^= 1L;
                vLo ^= polyLo;
            } else {
                vHi ^= (1L << shift) | (polyLo >>> (64 - shift));
                vLo ^= (polyLo << shift);
            }
        }
        return vLo;
    }

    /**
     * Galois Field multiplication in GF(2^64).
     */
    public static long gfMul64(long a, long b, long polyLo) {
        long[] prod = clmul64(a, b);
        return polyMod64(prod[0], prod[1], polyLo);
    }

    /**
     * Splits data into 64-bit chunks after bit-reversal and injectivity termination.
     */
    public static long[] messageChunks64(byte[] data) {
        int len = (data != null) ? data.length : 0;
        int paddedLen = ((len + 1 + 7) / 8) * 8;
        byte[] buf = new byte[paddedLen];

        if (data != null) {
            for (int i = 0; i < len; i++) {
                buf[i] = (byte) REVERSE_BYTE_TABLE[data[i] & 0xFF];
            }
        }
        buf[len] = 0x01; // Injectivity terminator bit

        int numChunks = paddedLen / 8;
        long[] chunks = new long[numChunks];
        ByteBuffer bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < numChunks; i++) {
            chunks[i] = bb.getLong();
        }
        return chunks;
    }

    /**
     * Evaluates 64-bit Toeplitz LFSR hash over message bytes.
     *
     * @param data Input byte array.
     * @param polyLo Lower 64 bits of irreducible polynomial (e.g. 0x1B for x^64 + x^4 + x^3 + x + 1).
     * @param seed Universal hash seed/key.
     * @return 64-bit hash digest.
     */
    public static long hash64(byte[] data, long polyLo, long seed) {
        long[] chunks = messageChunks64(data);
        long xN = polyLo; // x^64 mod p = polyLo

        long acc = 0;
        for (int i = chunks.length - 1; i >= 0; i--) {
            acc = gfMul64(acc, xN, polyLo) ^ chunks[i];
        }
        return gfMul64(acc, seed, polyLo);
    }
}
