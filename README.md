# QIDS Java SDK (`qids-java`)

[![Version](https://img.shields.io/badge/version-v1.4.1-blue.svg)](https://github.com/Raunakg2005/qids-java)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![JitPack](https://jitpack.io/v/Raunakg2005/qids-java.svg)](https://jitpack.io/#Raunakg2005/qids-java)

Java 17+ client for **Quantum Digital Signatures through a QIDS gateway**, with offline verification of the gateway's ML-DSA (FIPS 204) receipt signatures, an ETSI GS QKD 014 key-management client and Wald SPRT link monitoring.

From v1.4.0 the SDK depends on Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`) for ML-DSA; it uses the lightweight API and registers no JCA provider.

Signing and verification run on the gateway: the one-time universal-hash key is what makes a tag unforgeable, so a client able to compute tags locally could also forge them. `QIDSClient` authenticates with your API key and sends each payload as its exact bytes.

---

## Installation

### Gradle (via JitPack)

```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.Raunakg2005:qids-java:v1.4.1'
}
```

### Maven (via JitPack)

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.github.Raunakg2005</groupId>
        <artifactId>qids-java</artifactId>
        <version>v1.4.1</version>
    </dependency>
</dependencies>
```

---

## Quickstart

### 1. Sign and verify through the gateway

```java
import com.qids.QIDSClient;
import com.qids.SignResult;
import com.qids.SignatureTag;
import com.qids.VerifyResult;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        QIDSClient client = new QIDSClient(
                System.getenv("QIDS_GATEWAY_URL"), // your gateway's base URL
                "node-sae-01",
                System.getenv("QIDS_API_KEY"));    // sk_live_... / sk_test_...

        byte[] payload = "TRANSACTION_TRANSFER_USD_1000000".getBytes(StandardCharsets.UTF_8);
        SignResult sig = client.sign("DOC-98104", payload, List.of("node-sae-02"));
        SignatureTag tag = sig.getSignatureTags().get(0);

        VerifyResult result = client.verify("DOC-98104", payload, tag);
        System.out.println("valid=" + result.isValid() + " status=" + result.getStatus()
                + " threat=" + result.getThreat());
        // valid=true status=ACCEPTED threat=benign
    }
}
```

Document IDs are write-once per tenant: signing the same ID twice returns HTTP 409.
Payloads travel as `payload_b64`, so binary documents are signed byte-for-byte.
`verify(docId, payload, tag)` presents the tag as its recipient (`recipient_sae_id`), so each recipient's verification is attributed to that recipient. A `VerifyResult` carries the gateway's error rates and its threat attribution (`getThreat`, `getConfidence`, `getEvidence`).

Every request, to the gateway and to an ETSI KMS, is bounded by the client's timeout (10 s by default; pass a `Duration` to the constructor). A request that runs past it throws `java.net.http.HttpTimeoutException`.

#### Errors

A non-200 response throws `QIDSException` (an `IOException`) carrying the status code and the gateway's `error`, `message`, `reason` and `required_permission` fields. The common cases have their own subclasses:

```java
try {
    client.sign(docId, payload, recipients);
} catch (QIDSException.RateLimited e) {
    Thread.sleep(e.getRetryAfter().orElse(Duration.ofSeconds(60)).toMillis());
} catch (QIDSException.Unauthorized e) {  // 401: missing or invalid API key
} catch (QIDSException.Forbidden e) {     // 403: e.getRequiredPermission()
}
```

### 2. Verify a receipt offline (ML-DSA, FIPS 204)

From gateway 1.4.0, every sign response carries `getPqc()`: an ML-DSA signature over a statement about the document (tenant, document id, SHA3-256 hash, time, recipients, OTUH signature). Anyone with the tenant's public key can check it without contacting the gateway:

```java
import com.qids.PQCClaims;
import com.qids.PQCVerifier;
import com.qids.QIDSVerificationException;

// Once: fetch the tenant's public key and pin it (store it with your config).
String pinnedPem = client.getPqcKeys(tenantId).get(0).getPublicKeyPem(); // public endpoint; active key first

// Any time later, offline:
try {
    PQCClaims claims = PQCVerifier.verifyPqcReceipt(payload, sig.getPqc(), pinnedPem, tenantId);
    System.out.println(claims.getDocumentId() + " signed at " + claims.getSignedAtMs());
} catch (QIDSVerificationException e) {
    System.out.println("rejected: " + e.getReason().code()); // bad_signature, document_mismatch, tenant_mismatch, ...
}
```

`verifyPqcReceipt` checks the signature over the statement's exact bytes under the FIPS 204 context `qids-receipt-v1`, that the statement names this key (its id is the first 32 hex characters of SHA-256 over the raw key) and its parameter set (ML-DSA-44, -65 or -87), that the statement's `document_hash` is the SHA3-256 of `payload`, and the tenant (pass `null` to skip). A failure throws `QIDSVerificationException` (a `GeneralSecurityException`) whose `getReason()` names the check.

Take the public key from a source you trust, fetched once and pinned, never from the response you are checking. What the signature proves: the holder of the tenant's QIDS signing key attested this document at this time. The gateway holds that key on the tenant's behalf, so it is the gateway's attestation for the tenant.

### 3. ETSI GS QKD 014 key delivery client

```java
import com.qids.ETSI014Client;
import com.qids.ETSIKey;
import com.qids.ETSIStatus;
import java.util.List;

public class KeyConsumer {
    public static void main(String[] args) throws Exception {
        ETSI014Client etsi = new ETSI014Client("https://kms-appliance.telecom.net:8443", "SAE-Alice", "SAE-Bob");

        ETSIStatus status = etsi.getStatus();
        System.out.println("Available keys: " + status.getStoredKeyCount());

        List<ETSIKey> keys = etsi.getEncKeys(1, 256);
        for (ETSIKey k : keys) {
            System.out.printf("Key ID: %s (%d bits)%n", k.getKeyId(), k.getSizeBits());
        }
    }
}
```

A key that is neither base64 nor hex, or whose size differs from the one requested, throws `IOException` rather than being returned short.

### 4. Wald SPRT link monitor

```java
import com.qids.WaldSPRT;

public class OpticalMonitor {
    public static void main(String[] args) {
        // Honest error rate p0 = 0.02, attack threshold p1 = 0.1111, alpha = beta = 1e-4
        WaldSPRT detector = new WaldSPRT(0.02, 0.1111, 1e-4, 1e-4);

        // false = bit match, true = bit mismatch
        WaldSPRT.State state = detector.update(false);
        System.out.println("State: " + state); // CONTINUE, ACCEPT_H0 or ACCEPT_H1
    }
}
```

### Hash primitive (not a signature)

`QIDSClient.computeTag` / `verifyTag` expose the raw 64-bit Toeplitz universal hash. Anyone who knows the polynomial and seed can compute the same tag, so it is only as secret as those values are; use `sign` / `verify` above for signatures.

---

## Building from source

```bash
./gradlew build          # compiles and runs the tests
QIDS_TEST_GATEWAY_URL=... QIDS_TEST_API_KEY=... ./gradlew test   # also runs the live gateway test
```

---

## License

Strictly **Proprietary and Confidential**. Copyright &copy; 2026 QIDS. All Rights Reserved.
Unauthorized copying, decompilation, or redistribution is strictly prohibited. See [LICENSE](LICENSE).
