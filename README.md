# QIDS Java SDK (`qids-java`)

[![Version](https://img.shields.io/badge/version-v1.3.4-blue.svg)](https://github.com/Raunakg2005/qids-java)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![JitPack](https://jitpack.io/v/Raunakg2005/qids-java.svg)](https://jitpack.io/#Raunakg2005/qids-java)

Java 17+ client for **Quantum Digital Signatures through a QIDS gateway**, plus an ETSI GS QKD 014 key-management client and Wald SPRT link monitoring.

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
    implementation 'com.github.Raunakg2005:qids-java:v1.3.4'
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
        <version>v1.3.4</version>
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

        VerifyResult result = client.verify("DOC-98104", payload, tag.getHashTag(), tag.getKeyId());
        System.out.println("valid=" + result.isValid() + " status=" + result.getStatus());
        // valid=true status=ACCEPTED
    }
}
```

Document IDs are write-once per tenant: signing the same ID twice returns HTTP 409.
Payloads travel as `payload_b64`, so binary documents are signed byte-for-byte.

### 2. ETSI GS QKD 014 key delivery client

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

### 3. Wald SPRT link monitor

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
