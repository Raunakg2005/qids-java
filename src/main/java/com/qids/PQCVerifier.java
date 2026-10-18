package com.qids;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * Offline verification of a receipt's ML-DSA (FIPS 204) signature, with
 * Bouncy Castle. Nothing here contacts the gateway.
 *
 * Copyright (c) 2026 QIDS. All Rights Reserved.
 * Strictly Proprietary and Confidential.
 */
public final class PQCVerifier {

    /** The FIPS 204 context string the gateway signs receipts under. */
    public static final String CONTEXT = "qids-receipt-v1";

    private static final byte[] CONTEXT_BYTES = CONTEXT.getBytes(StandardCharsets.US_ASCII);
    private static final String PEM_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_END = "-----END PUBLIC KEY-----";

    private PQCVerifier() {}

    /** A parsed ML-DSA public key: its parameter set name, parameters and raw bytes. */
    static final class MLDSAKey {
        final String algorithm;
        final MLDSAPublicKeyParameters parameters;
        final byte[] raw;

        MLDSAKey(String algorithm, MLDSAPublicKeyParameters parameters, byte[] raw) {
            this.algorithm = algorithm;
            this.parameters = parameters;
            this.raw = raw;
        }
    }

    /**
     * Check a receipt's ML-DSA signature offline and return the signed claims.
     *
     * <p>The checks, in order (those of the Python SDK's verify_pqc_receipt):
     * the signature over the statement's exact bytes under the
     * {@value #CONTEXT} context; that the statement names this key (its id is
     * the first 32 hex characters of SHA-256 over the raw key) and its
     * parameter set; that the statement's document_hash_alg is SHA3-256 and
     * its document_hash is the SHA3-256 of {@code payload}; and, if given, the
     * tenant.
     *
     * @param payload      the document as signed
     * @param pqc          the receipt's "pqc" object ({@link SignResult#getPqc()})
     * @param publicKeyPem the tenant's key as PEM SubjectPublicKeyInfo, from a
     *                     source you trust ({@link QIDSClient#getPqcKeys} once,
     *                     then pinned), never from the response being checked
     * @param tenantId     the tenant the receipt must belong to; null to skip
     * @return the statement's claims
     * @throws QIDSVerificationException on any failed check; its reason names it
     */
    public static PQCClaims verifyPqcReceipt(byte[] payload, PQCReceipt pqc, String publicKeyPem, String tenantId)
            throws QIDSVerificationException {
        MLDSAKey key = parsePublicKey(publicKeyPem);
        byte[] statement = pqc == null ? null : decodeBase64(pqc.getStatement());
        byte[] signature = pqc == null ? null : decodeBase64(pqc.getSignature());
        if (statement == null || signature == null) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.MALFORMED_RECEIPT,
                    "the receipt has no valid base64 statement and signature");
        }
        if (!verifySignature(key.parameters, statement, signature, CONTEXT_BYTES)) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.BAD_SIGNATURE,
                    "ML-DSA signature does not verify under this key");
        }

        Map<String, Object> claims;
        try {
            claims = Json.parseObject(new String(statement, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.MALFORMED_RECEIPT,
                    "the signed statement is not a JSON object: " + e.getMessage());
        }
        if (!hex(digest("SHA-256", key.raw)).substring(0, 32).equals(claims.get("kid"))) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.KEY_MISMATCH,
                    "the statement names a different key");
        }
        if (!key.algorithm.equals(claims.get("alg"))) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.ALGORITHM_MISMATCH,
                    "the statement says " + claims.get("alg") + ", the key is " + key.algorithm);
        }
        byte[] document = payload == null ? new byte[0] : payload;
        if (!"SHA3-256".equals(claims.get("document_hash_alg"))
                || !hex(digest("SHA3-256", document)).equals(claims.get("document_hash"))) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.DOCUMENT_MISMATCH,
                    "the receipt is for a different document");
        }
        if (tenantId != null && !tenantId.equals(claims.get("tenant_id"))) {
            throw new QIDSVerificationException(QIDSVerificationException.Reason.TENANT_MISMATCH,
                    "the receipt belongs to a different tenant");
        }
        return new PQCClaims(claims, statement);
    }

    /** ML-DSA verification under a FIPS 204 context string; false on any malformed input. */
    static boolean verifySignature(MLDSAPublicKeyParameters key, byte[] message, byte[] signature, byte[] context) {
        try {
            MLDSASigner verifier = new MLDSASigner();
            verifier.init(false, new ParametersWithContext(key, context));
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Read a PEM SubjectPublicKeyInfo ML-DSA public key (RFC 9881). */
    static MLDSAKey parsePublicKey(String pem) throws QIDSVerificationException {
        if (pem == null) throw invalidKey("not a PEM public key");
        String text = pem.trim();
        if (!text.startsWith(PEM_BEGIN) || !text.endsWith(PEM_END)) throw invalidKey("not a PEM public key");
        String body = text.substring(PEM_BEGIN.length(), text.length() - PEM_END.length()).replaceAll("\\s", "");
        byte[] der = decodeBase64(body);
        if (der == null) throw invalidKey("not a PEM public key: bad base64");

        SubjectPublicKeyInfo spki;
        try {
            spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der));
        } catch (IOException | RuntimeException e) {
            throw invalidKey("not a PEM public key: bad SubjectPublicKeyInfo");
        }
        ASN1ObjectIdentifier oid = spki.getAlgorithm().getAlgorithm();
        String algorithm;
        MLDSAParameters parameters;
        if (NISTObjectIdentifiers.id_ml_dsa_44.equals(oid)) {
            algorithm = "ML-DSA-44";
            parameters = MLDSAParameters.ml_dsa_44;
        } else if (NISTObjectIdentifiers.id_ml_dsa_65.equals(oid)) {
            algorithm = "ML-DSA-65";
            parameters = MLDSAParameters.ml_dsa_65;
        } else if (NISTObjectIdentifiers.id_ml_dsa_87.equals(oid)) {
            algorithm = "ML-DSA-87";
            parameters = MLDSAParameters.ml_dsa_87;
        } else {
            throw invalidKey("the public key is not an ML-DSA key");
        }
        ASN1BitString bits = spki.getPublicKeyData();
        byte[] raw = bits.getOctets();
        // RFC 9881: no parameters; the key is the raw FIPS 204 encoding.
        if (spki.getAlgorithm().getParameters() != null || bits.getPadBits() != 0
                || raw.length != publicKeySize(algorithm)) {
            throw invalidKey("not a PEM public key: malformed " + algorithm + " key");
        }
        try {
            return new MLDSAKey(algorithm, new MLDSAPublicKeyParameters(parameters, raw), raw);
        } catch (RuntimeException e) {
            throw invalidKey("not a PEM public key: " + e.getMessage());
        }
    }

    private static int publicKeySize(String algorithm) {
        switch (algorithm) {
            case "ML-DSA-44": return 1312;
            case "ML-DSA-65": return 1952;
            default: return 2592;
        }
    }

    private static QIDSVerificationException invalidKey(String message) {
        return new QIDSVerificationException(QIDSVerificationException.Reason.INVALID_KEY, message);
    }

    /** Standard, padded base64 and nothing else; null when absent or invalid. */
    static byte[] decodeBase64(String s) {
        if (s == null || s.isEmpty() || s.length() % 4 != 0) return null;
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static byte[] digest(String algorithm, byte[] data) {
        try {
            return MessageDigest.getInstance(algorithm).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " is required by the Java platform", e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
