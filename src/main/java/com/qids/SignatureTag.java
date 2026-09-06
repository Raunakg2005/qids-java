package com.qids;

/**
 * Signature tag metadata for a specific recipient.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public class SignatureTag {
    private String recipientSaeId;
    private String hashTag;
    private int tagLengthBits;
    private String keyId;

    public SignatureTag() {}

    public SignatureTag(String recipientSaeId, String hashTag, int tagLengthBits, String keyId) {
        this.recipientSaeId = recipientSaeId;
        this.hashTag = hashTag;
        this.tagLengthBits = tagLengthBits;
        this.keyId = keyId;
    }

    public String getRecipientSaeId() { return recipientSaeId; }
    public void setRecipientSaeId(String recipientSaeId) { this.recipientSaeId = recipientSaeId; }

    public String getHashTag() { return hashTag; }
    public void setHashTag(String hashTag) { this.hashTag = hashTag; }

    public int getTagLengthBits() { return tagLengthBits; }
    public void setTagLengthBits(int tagLengthBits) { this.tagLengthBits = tagLengthBits; }

    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
}
