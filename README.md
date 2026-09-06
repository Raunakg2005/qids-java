# QIDS Java SDK (`qids-java`)

[![Version](https://img.shields.io/badge/version-v1.3.2-blue.svg)](https://github.com/Raunakg2005/qids-java)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![JitPack](https://jitpack.io/v/Raunakg2005/qids-java.svg)](https://jitpack.io/#Raunakg2005/qids-java)

Official Enterprise Java 17+ Client Library for the **Quantum Intrusion Detection System (QIDS)**.

Engineered for Spring Boot, Quarkus, telecom backends, and FinTech transaction networks requiring sub-millisecond quantum signature generation, ETSI GS QKD 014 Key Management System interoperability, and real-time Wald SPRT optical link monitoring.

---

## Installation

### Gradle (via JitPack)

Add the JitPack repository and dependency to your `build.gradle`:

```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.Raunakg2005:qids-java:v1.3.2'
}
```

### Maven (via JitPack)

Add to your `pom.xml`:

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
        <version>v1.3.2</version>
    </dependency>
</dependencies>
```

---

## Quickstart

### 1. Quantum Signature Generation & Verification (In-Process)

```java
import com.qids.QIDSClient;
import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {
        QIDSClient client = new QIDSClient("https://qids-daemon.internal:8443", "node-sae-01");

        byte[] payload = "TRANSACTION_TRANSFER_USD_1000000".getBytes(StandardCharsets.UTF_8);
        long polyLo = 0x1BL; // x^64 + x^4 + x^3 + x + 1
        long seed = 0xCAFEBABE12345678L;

        // Compute 64-bit universal hash tag
        long tag = client.computeTag(payload, polyLo, seed);
        System.out.printf("Computed Tag: 0x%016X%n", tag);

        // Constant-time verification
        boolean isValid = client.verifyTag(payload, tag, polyLo, seed);
        System.out.println("Signature Valid: " + isValid);
    }
}
```

### 2. ETSI GS QKD 014 Key Delivery REST Client

```java
import com.qids.ETSI014Client;
import com.qids.ETSIKey;
import com.qids.ETSIStatus;
import java.util.List;

public class KeyConsumer {
    public static void main(String[] args) throws Exception {
        ETSI014Client etsi = new ETSI014Client("https://kms-appliance.telecom.net:8443", "SAE-Alice", "SAE-Bob");

        // Query key availability status
        ETSIStatus status = etsi.getStatus();
        System.out.println("Available Quantum Keys: " + status.getStoredKeyCount());

        // Request encryption keys (Alice)
        List<ETSIKey> keys = etsi.getEncKeys(1, 256);
        for (ETSIKey k : keys) {
            System.out.printf("Key ID: %s (%d bits)%n", k.getKeyId(), k.getSizeBits());
        }
    }
}
```

### 3. Real-Time Physical-Layer Threat Detector (Wald SPRT)

```java
import com.qids.WaldSPRT;

public class OpticalMonitor {
    public static void main(String[] args) {
        // Honest error rate p0 = 0.02, attack threshold p1 = 0.1111, false alarm alpha = 1e-4
        WaldSPRT detector = new WaldSPRT(0.02, 0.1111, 1e-4, 1e-4);

        // Stream quantum measurement observations (false = match, true = bit mismatch)
        WaldSPRT.State state = detector.update(false);
        System.out.println("Current Threat State: " + state); // CONTINUE, ACCEPT_H0, ACCEPT_H1
    }
}
```

---

## License

Strictly **Proprietary and Confidential**. Copyright &copy; 2026 QIDS. All Rights Reserved.  
Unauthorized copying, decompilation, or redistribution is strictly prohibited. See [LICENSE](LICENSE).
