package com.qids;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a quantum key slice delivered by an ETSI GS QKD 014 appliance.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class ETSIKey {
    private final String keyId;
    private final byte[] keyBytes;
    private final int sizeBits;

    public ETSIKey(String keyId, byte[] keyBytes, int sizeBits) {
        this.keyId = keyId;
        this.keyBytes = (keyBytes != null) ? keyBytes.clone() : new byte[0];
        this.sizeBits = sizeBits;
    }

    public String getKeyId() {
        return keyId;
    }

    public byte[] getKeyBytes() {
        return keyBytes.clone();
    }

    public int getSizeBits() {
        return sizeBits;
    }

    /**
     * Converts key bytes into a list of binary integers (0 or 1).
     */
    public List<Integer> toBitList() {
        List<Integer> bits = new ArrayList<>(sizeBits);
        for (byte b : keyBytes) {
            for (int shift = 7; shift >= 0; shift--) {
                bits.add((b >>> shift) & 1);
                if (bits.size() == sizeBits) {
                    return bits;
                }
            }
        }
        return bits;
    }
}
