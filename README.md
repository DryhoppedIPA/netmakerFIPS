  <h1>Netmaker FIPS-Compliant Deployment: Getting Started Guide</h1>

  <p>This guide walks you through setting up a fully FIPS 140-3–compliant Netmaker server (and clients) on Ubuntu 22.04 LTS with wolfSSL/wolfCrypt. It covers:</p>

  <ol>
    <li>Prerequisites &amp; Ubuntu Pro setup</li>
    <li>wolfSSL/wolfCrypt installation (FIPS-ready)</li>
    <li>Compiling <code>wireguard-go-fips</code></li>
    <li>Netmaker build &amp; configuration (including Go build tags)</li>
    <li>Verifying FIPS compliance at runtime</li>
    <li>Security considerations for commercial deployments</li>
    <li>Commercial wolfSSL licensing reminder</li>
    <li>Contact Netmaker for self-hosting licenses</li>
    <li>Useful links &amp; references</li>
  </ol>

  <hr />

  <h2>1. Prerequisites &amp; Ubuntu Pro Setup</h2>

  <h3>1.1. Hardware &amp; VM Requirements</h3>
  <ul>
    <li><strong>VM or bare-metal</strong> running Ubuntu 22.04 LTS (64 bit).</li>
    <li>Minimum <strong>2 vCPUs, 2 GB RAM</strong>, and <strong>20 GB disk</strong> for building and running Netmaker.</li>
    <li>Ensure you have <strong>root</strong> (or sudo) privileges.</li>
  </ul>

  <h3>1.2. Ubuntu Pro Subscription (Free for Personal Use)</h3>
  <p>Ubuntu Pro provides a FIPS-enabled kernel and FIPS-validated userland packages. For up to 5 machines (personal or small business), the subscription is <strong>free</strong>. If you need more than 5 machines or phone support, choose the “My organisation” (paid) option.</p>

  <ol>
    <li><strong>Sign up for Ubuntu Pro</strong>
      <ul>
        <li>Visit <a href="https://ubuntu.com/pro">ubuntu.com/pro</a>.</li>
        <li>Select “Myself” (free, up to 5 machines).</li>
        <li>Complete registration; note your Ubuntu Pro token.</li>
      </ul>
    </li>
    <li><strong>Attach &amp; Enable FIPS on the VM</strong>
      <pre><code class="language-bash">sudo apt update
sudo apt install ubuntu-advantage-tools
sudo pro attach &lt;YOUR_UBUNTU_PRO_TOKEN&gt;
sudo pro enable fips
sudo apt install ubuntu-fips
sudo reboot
</code></pre>
      <p>After reboot, verify:</p>
      <pre><code>$ cat /proc/sys/crypto/fips_enabled
1
</code></pre>
      <p>If it prints <code>1</code>, your host is now using a FIPS-enabled kernel.</p>
      <blockquote>
        <p><strong>Note</strong>: Simply installing <code>ubuntu-fips</code> inside a container is <strong>not</strong> enough—containers inherit the host kernel. The host VM itself must be FIPS-enabled to satisfy compliance.</p>
      </blockquote>
    </li>
  </ol>

  <hr />

  <h2>2. Install wolfSSL/wolfCrypt (FIPS-Ready)</h2>
  <p>wolfSSL/wolfCrypt must be built with <code>--enable-fips=ready</code> to produce a FIPS 140-3–validated cryptographic engine. These steps assume you have the 5.8.0 “FIPS-Ready” source in a local folder (or under <code>vendor/wolfssl/</code>).</p>

  <h3>2.1. Install Build Tools</h3>
  <pre><code class="language-bash">sudo apt update
sudo apt install -y \
  build-essential autoconf automake libtool pkg-config git wget
</code></pre>

  <h3>2.2. Prepare wolfCrypt &amp; wolfSSL Source</h3>
  <p>If you haven’t already, clone or copy the FIPS-Ready sources:</p>
  <pre><code class="language-bash"># Example: cloning official repo at the v5.8.0 FIPS tag
cd ~
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
git checkout v5.8.0-gplv3-fips-ready
</code></pre>
  <p>Alternatively, if you maintain a <code>vendor/wolfssl/</code> folder in your Netmaker project, simply <code>cd</code> into that.</p>

  <h3>2.3. Build &amp; Install wolfCrypt</h3>
  <pre><code class="language-bash">cd wolfssl/wolfcrypt
./autogen.sh       # only if present; otherwise skip
./configure --enable-fips=ready --disable-opensslextra
make
sudo make install
sudo ldconfig
</code></pre>
  <p>After installation, verify the FIPS self-test:</p>
  <pre><code>$ strings /usr/local/lib/libwolfcrypt.so | grep "wolfCrypt FIPS self-test passed"
</code></pre>
  <p>You should see a line like:</p>
  <pre><code>wolfCrypt FIPS self-test passed
</code></pre>

  <h3>2.4. Build &amp; Install wolfSSL</h3>
  <pre><code class="language-bash">cd ../wolfssl
./autogen.sh       # if present
./configure --enable-fips=ready \
            --with-wolfcrypt=/usr/local \
            --disable-opensslextra
make
sudo make install
sudo ldconfig
</code></pre>
  <p>Verify:</p>
  <pre><code>$ strings /usr/local/lib/libwolfssl.so | grep "wolfCrypt FIPS self-test passed"
</code></pre>

  <p>After these steps, your system libraries (<code>/usr/local/lib</code>) contain FIPS-validated wolfCrypt and wolfSSL. Using these libraries (version 5.8.0) maintains FIPS validation through <strong>July 10, 2029</strong>. No additional FIPS module revalidation is needed, provided you do not upgrade to a wolfSSL/wolfCrypt version without a valid FIPS certificate.</p>

  <hr />

  <h2>3. Compile <code>wireguard-go-fips</code></h2>
  <p>We need a WireGuard-GO binary that uses wolfCrypt as its crypto backend. The “OSP” repository from wolfSSL contains the necessary patches.</p>

  <h3>3.1. Install Go (if not already)</h3>
  <pre><code class="language-bash">wget https://go.dev/dl/go1.20.7.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.20.7.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
</code></pre>
  <p>Verify:</p>
  <pre><code>$ go version
go version go1.20.7 linux/amd64
</code></pre>

  <h3>3.2. Clone the OSP Repo &amp; Build</h3>
  <pre><code class="language-bash">cd ~
git clone https://github.com/wolfSSL/osp.git
cd osp/wireguard-go
</code></pre>
  <p>Set CGO flags to link against wolfSSL/wolfCrypt:</p>
  <pre><code class="language-bash">export CGO_CFLAGS="-I/usr/local/include -DFIPS"
export CGO_LDFLAGS="-L/usr/local/lib -lwolfssl -lwolfcrypt"
</code></pre>
  <p>Build:</p>
  <pre><code class="language-bash">go build -o /usr/local/bin/wireguard-go-fips ./cmd/wireguard-go
</code></pre>
  <p>Verify FIPS build:</p>
  <pre><code class="language-bash">$ strings /usr/local/bin/wireguard-go-fips | grep -q "wolfCrypt FIPS"
echo "✅ wireguard-go-fips includes wolfCrypt FIPS"
</code></pre>
  <p>You now have a <code>wireguard-go-fips</code> binary that enforces P-256, AES-GCM, SHA-256 only. It links against wolfCrypt 5.8.0’s FIPS engine, maintaining FIPS validation without additional steps.</p>
  <blockquote>
    <p><strong>Optional</strong>: If Netmaker expects <code>wireguard-go</code>, create a symlink:</p>
    <pre><code class="language-bash">sudo ln -s /usr/local/bin/wireguard-go-fips /usr/local/bin/wireguard-go
</code></pre>
  </blockquote>

  <hr />

  <h2>4. Build &amp; Configure Netmaker</h2>
  <p>Our goal is to compile Netmaker so that any key generation uses wolfCrypt’s FIPS routines instead of Go’s ECDSA stubs.</p>

  <h3>4.1. GitHub Repo Structure (Example)</h3>
  <pre><code>netmakerFIPS/
├─ controllers/
├─ logic/
│  ├─ fips_validation.go
│  ├─ fips_stubs.go            # stubbed ECDSA implementation (build tag !fips)
│  ├─ fips_wolfcrypt.go        # CGO wrapper to wolfCrypt (build tag fips)
│  └─ fips_validation_test.go
├─ models/
│  ├─ json_types.go
│  └─ fips_peer.go
├─ metrics/
│  └─ fips_metrics.go
├─ scripts/
│  └─ verify_fips_compliance.sh
├─ test/
│  └─ fips_integration.sh
├─ migrations/
│  └─ 001_fips_keys.up.sql
├─ Dockerfile.fips
├─ main.go
├─ go.mod
├─ go.sum
└─ vendor/
   └─ wolfssl/                # wolfCrypt & wolfSSL FIPS sources (if vendored)
</code></pre>

  <h3>4.2. <code>fips_validation.go</code> (On-Curve Validation)</h3>
  <pre><code>package logic

import (
    "crypto/elliptic"
    "encoding/base64"
    "errors"
    "fmt"

    "github.com/gravitl/netmaker/metrics"
)

func ValidatePublicKey(keyB64 string) error {
    decoded, err := base64.StdEncoding.DecodeString(keyB64)
    if err != nil {
        metrics.KeysValidated.WithLabelValues("invalid").Inc()
        return fmt.Errorf("invalid base64 encoding: %w", err)
    }
    if len(decoded) != 65 {
        metrics.KeysValidated.WithLabelValues("invalid").Inc()
        return fmt.Errorf("invalid key length: got %d bytes, expected 65", len(decoded))
    }
    if decoded[0] != 0x04 {
        metrics.KeysValidated.WithLabelValues("invalid").Inc()
        return fmt.Errorf("invalid key prefix: expected 0x04, got 0x%02x", decoded[0])
    }
    x, y := elliptic.Unmarshal(elliptic.P256(), decoded)
    if x == nil || y == nil {
        metrics.KeysValidated.WithLabelValues("invalid").Inc()
        return errors.New("invalid P-256 key: point not on the curve")
    }
    metrics.KeysValidated.WithLabelValues("valid").Inc()
    return nil
}
</code></pre>
  <p>This validation is the same in both stub and production. The difference is how you <strong>generate</strong> and <strong>serialize</strong> keys (via stubs or via wolfCrypt).</p>

  <h3>4.3. <code>fips_stubs.go</code> (Stubbed ECDSA)</h3>
  <pre><code>//go:build !fips
// +build !fips

package logic

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "math/big"
)

// NOTE: These stubs use Go’s crypto/ecdsa. Not for production.

func GenerateP256KeyPair() (*ecdsa.PrivateKey, string, error) {
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, "", fmt.Errorf("failed to generate P-256 key pair: %w", err)
    }
    pubRaw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
    pubB64 := base64.StdEncoding.EncodeToString(pubRaw)
    return priv, pubB64, nil
}

func SerializeP256PrivateKey(priv *ecdsa.PrivateKey) (string, error) {
    if priv == nil {
        return "", errors.New("cannot serialize nil private key")
    }
    privBytes := priv.D.Bytes()
    if len(privBytes) > 32 {
        return "", fmt.Errorf("unexpected private key size: %d bytes", len(privBytes))
    }
    padded := make([]byte, 32)
    copy(padded[32-len(privBytes):], privBytes)
    return base64.StdEncoding.EncodeToString(padded), nil
}

func DeserializeP256PrivateKey(privB64 string) (*ecdsa.PrivateKey, error) {
    decoded, err := base64.StdEncoding.DecodeString(privB64)
    if err != nil {
        return nil, fmt.Errorf("invalid base64 for private key: %w", err)
    }
    if len(decoded) != 32 {
        return nil, fmt.Errorf("invalid private key length: got %d bytes, expected 32", len(decoded))
    }
    D := new(big.Int).SetBytes(decoded)
    priv := new(ecdsa.PrivateKey)
    priv.PublicKey.Curve = elliptic.P256()
    priv.D = D
    priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(decoded)
    if priv.PublicKey.X == nil || priv.PublicKey.Y == nil {
        return nil, errors.New("failed to derive public key from private key bytes")
    }
    return priv, nil
}
</code></pre>
  <p><strong>Build tag</strong> <code>//go:build !fips</code> ensures this file is included only in non-FIPS builds (e.g., local dev, unit tests). <strong>Do not</strong> use these functions in production.</p>

  <h3>4.4. <code>fips_wolfcrypt.go</code> (Production)</h3>
  <pre><code>//go:build fips
// +build fips

package logic

/*
#cgo CFLAGS: -I${SRCDIR}/../vendor/wolfssl/wolfcrypt
#cgo LDFLAGS: -L/usr/local/lib -lwolfssl -lwolfcrypt -ldl

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/options.h>
#include <stdint.h>
#include <stdlib.h>

// wc_generate_p256: generate a 65-byte uncompressed pubkey and 32-byte privkey
static int wc_generate_p256(uint8_t** pubRaw, uint32_t* pubLen,
                            uint8_t** privRaw, uint32_t* privLen) {
    int ret;
    WC_RNG rng;
    ecc_key key;
    uint8_t* pbuf = (uint8_t*)malloc(65);
    uint8_t* dbuf = (uint8_t*)malloc(32);
    if (pbuf == NULL || dbuf == NULL) {
        if (pbuf) free(pbuf);
        if (dbuf) free(dbuf);
        return -1;
    }
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        free(pbuf);
        free(dbuf);
        return ret;
    }
    ret = wc_ecc_init(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        free(pbuf);
        free(dbuf);
        return ret;
    }
    ret = wc_ecc_make_key(&rng, 32, &key);
    if (ret != 0) {
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        free(pbuf);
        free(dbuf);
        return ret;
    }
    *pubLen = 65;
    ret = wc_ecc_export_x963(&key, pbuf, pubLen);
    if (ret != 0) {
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        free(pbuf);
        free(dbuf);
        return ret;
    }
    *privLen = 32;
    ret = wc_ecc_export_private_only(&key, dbuf, privLen);
    if (ret != 0) {
        wc_ecc_free(&key);
        wc_FreeRng(&rng);
        free(pbuf);
        free(dbuf);
        return ret;
    }
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    *pubRaw = pbuf;
    *privRaw = dbuf;
    return 0;
}
*/
import "C"
import (
    "encoding/base64"
    "errors"
    "fmt"
    "unsafe"
)

// GenerateP256KeyPair calls wolfCrypt’s FIPS routines to produce a raw 32-byte private key and 65-byte public key.
func GenerateP256KeyPair() (*[32]byte, string, error) {
    var pubPtr *C.uint8_t
    var privPtr *C.uint8_t
    var pubLen C.uint32_t
    var privLen C.uint32_t

    ret := C.wc_generate_p256(&pubPtr, &pubLen, &privPtr, &privLen)
    if int(ret) != 0 {
        return nil, "", fmt.Errorf("wolfCrypt wc_generate_p256 failed: %d", int(ret))
    }
    if pubLen != 65 || privLen != 32 {
        C.free(unsafe.Pointer(pubPtr))
        C.free(unsafe.Pointer(privPtr))
        return nil, "", fmt.Errorf("unexpected key lengths from wolfCrypt: pub %d, priv %d", int(pubLen), int(privLen))
    }
    pubBuf := C.GoBytes(unsafe.Pointer(pubPtr), C.int(pubLen))
    pubB64 := base64.StdEncoding.EncodeToString(pubBuf)
    privBuf := C.GoBytes(unsafe.Pointer(privPtr), C.int(privLen))
    var privArray [32]byte
    copy(privArray[:], privBuf)
    C.free(unsafe.Pointer(pubPtr))
    C.free(unsafe.Pointer(privPtr))
    return &privArray, pubB64, nil
}

func SerializeP256PrivateKey(priv *[32]byte) (string, error) {
    if priv == nil {
        return "", errors.New("cannot serialize nil private key")
    }
    return base64.StdEncoding.EncodeToString(priv[:]), nil
}

func DeserializeP256PrivateKey(privB64 string) (*[32]byte, error) {
    decoded, err := base64.StdEncoding.DecodeString(privB64)
    if err != nil {
        return nil, fmt.Errorf("invalid base64 for private key: %w", err)
    }
    if len(decoded) != 32 {
        return nil, fmt.Errorf("invalid private key length: got %d bytes, expected 32", len(decoded))
    }
    var privArr [32]byte
    copy(privArr[:], decoded)
    return &privArr, nil
}
</code></pre>
  <p><strong>Build tag</strong> <code>//go:build fips</code> ensures this file is included only in FIPS mode. CGO directives link against <code>/usr/local/lib/libwolfcrypt.so</code> and <code>/usr/local/lib/libwolfssl.so</code>. The helper C function <code>wc_generate_p256</code> calls wolfCrypt’s FIPS routines (<code>wc_ecc_make_key</code>, <code>wc_ecc_export_x963</code>, etc.) to produce a <strong>65-byte</strong> uncompressed public key and a <strong>32-byte</strong> private scalar.</p>

  <hr />

  <h2>5. Build Workflow</h2>

  <h3>5.1. Unit Testing (Non-FIPS / Local Dev)</h3>
  <pre><code class="language-bash">go test ./logic
</code></pre>
  <ul>
    <li>No <code>fips</code> tag → Go includes <code>fips_stubs.go</code> (ECDSA stubs).</li>
    <li>You can run <code>fips_validation_test.go</code> to verify on-curve validation and stub serialization.</li>
  </ul>

  <h3>5.2. Production Build (FIPS Mode)</h3>
  <p>Ensure wolfCrypt/wolfSSL FIPS libraries are installed in <code>/usr/local</code>. Then:</p>
  <pre><code class="language-bash">go build -tags fips -o /usr/local/bin/netmaker-server ./cmd/netmaker
</code></pre>
  <p><code>-tags fips</code> tells Go to compile <code>fips_wolfcrypt.go</code> and omit <code>fips_stubs.go</code>. The resulting <code>netmaker-server</code> binary will invoke wolfCrypt’s FIPS functions for all key generation and serialization.</p>
  <blockquote>
    <p><strong>Docker Build (Example)</strong>: In <code>Dockerfile.fips</code>, use:</p>
    <pre><code class="language-bash">RUN go build -tags fips -o /usr/local/bin/netmaker-server ./cmd/netmaker
</code></pre>
  </blockquote>

  <hr />

  <h2>6. Runtime Verification of FIPS Compliance</h2>
  <p>After building and deploying <code>netmaker-server</code>, you should verify:</p>
  <ol>
    <li><strong>OS-Level FIPS Flag</strong>
      <pre><code>$ cat /proc/sys/crypto/fips_enabled
1
</code></pre>
      <p>If this is <code>0</code> or missing, FIPS is not enabled on the host kernel.</p>
    </li>
    <li><strong>wolfCrypt Self-Test</strong>
      <pre><code>$ strings /usr/local/lib/libwolfcrypt.so | grep "wolfCrypt FIPS self-test passed"
</code></pre>
      <p>Should display “wolfCrypt FIPS self-test passed” at least once.</p>
    </li>
    <li><strong><code>wireguard-go-fips</code> Build</strong>
      <pre><code>$ wireguard-go --version
# should include “wolfCrypt FIPS”
</code></pre>
      <p>or</p>
      <pre><code>$ strings /usr/local/bin/wireguard-go-fips | grep "wolfCrypt FIPS"
</code></pre>
    </li>
    <li><strong><code>netmaker-server</code> Binary</strong>
      <pre><code>$ strings /usr/local/bin/netmaker-server | grep "wc_generate_p256"
</code></pre>
      <p>The presence of <code>wc_generate_p256</code> indicates your binary calls wolfCrypt’s FIPS keygen.</p>
    </li>
    <li><strong>Netmaker “verifyFIPSEnvironment” Check</strong>
      <p>In <code>main.go</code>, you might have:</p>
      <pre><code>func verifyFIPSEnvironment() {
    // OS-level FIPS
    data, _ := ioutil.ReadFile("/proc/sys/crypto/fips_enabled")
    if strings.TrimSpace(string(data)) != "1" {
        log.Fatal("FIPS mode not enabled on host")
    }
    // wireguard-go check
    out, _ := exec.Command("wireguard-go", "--version").Output()
    if !strings.Contains(string(out), "wolfCrypt FIPS") {
        log.Fatal("wireguard-go is not a wolfCrypt FIPS build")
    }
}

func main() {
    verifyFIPSEnvironment()
    // ...
}
</code></pre>
    </li>
    <li><strong>Prometheus Metrics</strong>
      <pre><code>netmaker_fips_keys_validated_total{status="valid"}  0
netmaker_fips_keys_validated_total{status="invalid"} 0
netmaker_fips_handshake_failures_total             0
</code></pre>
      <p>via <code>curl http://localhost:8080/metrics</code>.</p>
    </li>
  </ol>

  <hr />

  <h2>7. Security Considerations &amp; Best Practices</h2>

  <h3>7.1. Host Hardening &amp; CIS Compliance</h3>
  <ul>
    <li><strong>CIS Ubuntu 22.04 Benchmark</strong>: Follow hardening recommendations (Ubuntu Pro automations handle many).</li>
    <li><strong>Disk Encryption</strong>: Use LUKS (optionally with TPM for key escrow).</li>
    <li><strong>SSH Hardening</strong>: Disable <code>PermitRootLogin</code>, require key-based auth only.</li>
    <li><strong>Firewall</strong>: Enable UFW or iptables to restrict ports (only 8080 and 51820/UDP as needed).</li>
    <li><strong>Unattended Upgrades</strong>:
      <pre><code>sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
</code></pre>
    </li>
  </ul>

  <h3>7.2. Network Segmentation</h3>
  <ul>
    <li>Ensure only authorized subnets or bastion hosts can reach the Netmaker API (port 8080) and WireGuard UDP port (51820).</li>
    <li>Use security groups or ACLs (AWS/Azure/GCP) to isolate management, control, and data planes.</li>
  </ul>

  <h3>7.3. Logging &amp; Monitoring</h3>
  <ul>
    <li><strong>Auditd</strong>:
      <pre><code>sudo apt install auditd
sudo systemctl enable auditd && sudo systemctl start auditd
</code></pre>
      <p>Log privileged operations and configuration changes.</p>
    </li>
    <li><strong>Prometheus/Grafana</strong>:
      <ul>
        <li>Track FIPS metrics (<code>KeysValidated</code>, <code>HandshakeFailures</code>).</li>
        <li>Alert on spikes in invalid key validations or handshake failures (> 0.1%).</li>
        <li>Retain logs for at least 180 days (or as your compliance policy dictates).</li>
      </ul>
    </li>
  </ul>

  <h3>7.4. Container &amp; Runtime Security</h3>
  <ul>
    <li>If using Docker, ensure the host’s <code>/proc/sys/crypto/fips_enabled == 1</code>.</li>
    <li>Build images from <code>Dockerfile.fips</code> only on a FIPS-enabled host.</li>
    <li>Use Docker’s user-namespace remapping or run with minimal privileges (<code>--cap-drop ALL</code>, then <code>--cap-add NET_ADMIN</code> if needed).</li>
    <li>Scan container images regularly (e.g. Trivy, Clair) and rebuild frequently to incorporate security patches.</li>
  </ul>

  <h3>7.5. Key Protection &amp; Rotation</h3>
  <ul>
    <li>Do <strong>not</strong> store private keys in plaintext on disk.</li>
    <li>If Netmaker must persist a client’s P-256 private key (e.g., auto-provisioned external peers), encrypt it at rest (using Vault, GPG, or similar).</li>
    <li>Set file permissions to <code>600</code> so only the Netmaker user can read.</li>
    <li>Rotate keys every 90 days—generate new P-256 pairs, update WireGuard peers, and retire old keys.</li>
  </ul>

  <h3>7.6. Periodic FIPS Re-Validation</h3>
  <ul>
    <li>wolfCrypt’s FIPS 140-3 certificate (#4718) is valid through <strong>July 10, 2029</strong>.</li>
    <li><strong>Library Version</strong>: If you upgrade wolfSSL/wolfCrypt to a version without the same certificate, you lose FIPS compliance. Always verify the new version’s CMVP status before upgrading.</li>
    <li><strong>OS-Level Changes</strong>: Switching to a non-FIPS kernel or disabling <code>fips=1</code> at boot breaks compliance. If you update the kernel, ensure you remain on a FIPS-approved kernel package and re-enable FIPS.</li>
  </ul>
  <blockquote>
    <p><strong>Tip</strong>: Subscribe to the <a href="https://www.wolfssl.com/license/fips/">wolfCrypt FIPS page</a> and <a href="https://csrc.nist.gov/projects/cryptographic-module-validation-program">NIST CMVP</a> for certificate updates.</p>
  </blockquote>

  <hr />

  <h2>8. Commercial wolfSSL Licensing Reminder</h2>
  <ul>
    <li><strong>wolfSSL Licensing</strong>: If you deploy Netmaker in a <strong>commercial</strong> environment (outside the free or community scopes), you must purchase a <strong>one-time</strong> commercial license from wolfSSL.</li>
    <li>This license fee underwrites ongoing FIPS maintenance and support. It's the right thing to do &amp; without it, you cannot legally distribute or use wolfCrypt’s FIPS libraries in a commercial product.</li>
    <li>Typical cost: <strong>~$6 000</strong> (may change in the future). This covers a FIPS-validated Meraki-class router + license extension—much more cost-effective than replacing your network with proprietary hardware that requires annual licenses (switches, firewalls, etc.).</li>
    <li>Contact <a href="https://www.wolfssl.com/contact/">wolfSSL Sales</a> or check their <a href="https://www.wolfssl.com/licenses/">pricing page</a> for details.</li>
  </ul>

  <hr />

  <h2>9. Contact Netmaker for Self-Hosting Licenses</h2>
  <p>To keep open-source projects like Netmaker thriving and funded, please reach out for a <strong>self-hosting license</strong> when deploying in production. Licensing proceeds help support ongoing development, maintenance, and community resources. Contact <a href="https://www.netmaker.io/contact">Netmaker Sales</a> or email <a href="mailto:sales@netmaker.io">sales@netmaker.io</a> for details and pricing.</p>

  <hr />

  <h2>10. Additional References &amp; Links</h2>
  <ul>
    <li>wolfSSL FIPS 140-3 Cert #4718: <a href="https://www.wolfssl.com/license/fips/">https://www.wolfssl.com/license/fips/</a></li>
    <li>NIST CMVP listings: <a href="https://csrc.nist.gov/projects/cryptographic-module-validation-program">https://csrc.nist.gov/projects/cryptographic-module-validation-program</a></li>
    <li>CIS Ubuntu 22.04 Benchmark: <a href="https://www.cisecurity.org/benchmark/ubuntu_linux/">https://www.cisecurity.org/benchmark/ubuntu_linux/</a></li>
    <li>Ubuntu Pro (free for up to 5 machines): <a href="https://ubuntu.com/pro">https://ubuntu.com/pro</a></li>
    <li>wolfSSL/OSP (patched WireGuard GO): <a href="https://github.com/wolfSSL/osp">https://github.com/wolfSSL/osp</a></li>
    <li>Netmaker Documentation: <a href="https://github.com/gravitl/netmaker">https://github.com/gravitl/netmaker</a></li>
    <li>FIPS Integration Test Script: <code>test/fips_integration.sh</code> (in this repo)</li>
    <li>Compliance Verification Script: <code>scripts/verify_fips_compliance.sh</code></li>
  </ul>

  <hr />

  <h2>11. Quick‐Start Checklist</h2>
  <p>Before marking this deployment as production-ready, ensure:</p>
  <ul>
    <li><input type="checkbox" disabled /> Host VM is Ubuntu 22.04 LTS, attached to Ubuntu Pro, and in FIPS mode.</li>
    <li><input type="checkbox" disabled /> wolfCrypt and wolfSSL built/installed with <code>--enable-fips=ready</code> (version 5.8.0 or another valid FIPS release).</li>
    <li><input type="checkbox" disabled /> <code>wireguard-go-fips</code> compiled and verified (<code>strings | grep "wolfCrypt FIPS"</code>).</li>
    <li><input type="checkbox" disabled /> Netmaker built with <code>go build -tags fips</code>.</li>
    <li><input type="checkbox" disabled /> Runtime verification:
      <ul>
        <li><code>/proc/sys/crypto/fips_enabled == 1</code></li>
        <li><code>wireguard-go-fips --version</code> includes “wolfCrypt FIPS”</li>
        <li><code>strings netmaker-server | grep "wc_generate_p256"</code></li>
      </ul>
    </li>
    <li><input type="checkbox" disabled /> Prometheus metrics exposed at <code>/metrics</code> and showing zero invalid keys / handshake failures.</li>
    <li><input type="checkbox" disabled /> OS hardened according to CIS benchmark.</li>
    <li><input type="checkbox" disabled /> Firewall rules restrict access to 8080 and 51820/UDP only.</li>
    <li><input type="checkbox" disabled /> Logging/auditing (auditd, Prometheus) configured.</li>
    <li><input type="checkbox" disabled /> Secrets (private keys) encrypted at rest with appropriate permissions.</li>
    <li><input type="checkbox" disabled /> Commercial deployment: <strong>wolfSSL commercial license acquired</strong>.</li>
    <li><input type="checkbox" disabled /> <strong>Self-hosting license from Netmaker obtained</strong>.</li>
  </ul>
  <p>Once all items are checked, you have a fully FIPS 140-3–compliant Netmaker server on Ubuntu 22.04 LTS using wolfSSL’s FIPS-ready wolfCrypt. Good luck!</p>

  <hr />

  <h2>12. Disclaimer &amp; Use at Your Own Risk</h2>
  <p>This guide and associated code are provided <strong>"AS IS"</strong> without any warranties or guarantees. Gaura Allen and RBTS are <strong>not responsible</strong> for any issues, data loss, or security incidents resulting from using or modifying this guide or code. Use at your own risk.</p>
  <p><strong>Recommendations:</strong></p>
  <ul>
    <li>Always review and audit the codebase before deploying to production, especially given the sensitive nature of cryptographic and network configuration.</li>
    <li>Test in a controlled environment before rolling out to critical systems.</li>
    <li>Ensure you comply with your organization’s security policies and any applicable regulations.</li>
  </ul>

<p align="center">
  <a href="https://netmaker.io">
  <img src="https://raw.githubusercontent.com/gravitl/netmaker-docs/master/images/netmaker-github/netmaker-teal.png" width="50%"><break/>
  </a>
</p>

<p align="center">
<a href="https://runacap.com/ross-index/annual-2022/" target="_blank" rel="noopener">
    <img src="https://runacap.com/wp-content/uploads/2023/02/Annual_ROSS_badge_white_2022.svg" alt="ROSS Index - Fastest Growing Open-Source Startups | Runa Capital" width="17%" />
</a>  
<a href="https://www.ycombinator.com/companies/netmaker/" target="_blank" rel="noopener">
    <img src="https://raw.githubusercontent.com/gravitl/netmaker-docs/master/images/netmaker-github/y-combinator.png" alt="Y-Combinator" width="16%" />
</a>  
</p>

<p align="center">
  <a href="https://github.com/gravitl/netmaker/releases">
    <img src="https://img.shields.io/badge/Version-0.90.0-informational?style=flat-square" />
  </a>
  <a href="https://hub.docker.com/r/gravitl/netmaker/tags">
    <img src="https://img.shields.io/docker/pulls/gravitl/netmaker?label=downloads" />
  </a>  
  <a href="https://goreportcard.com/report/github.com/gravitl/netmaker">
    <img src="https://goreportcard.com/badge/github.com/gravitl/netmaker" />
  </a>
  <a href="https://twitter.com/intent/follow?screen_name=netmaker_io">
    <img src="https://img.shields.io/twitter/follow/netmaker_io?label=follow&style=social" />
  </a>
  <a href="https://www.youtube.com/channel/UCach3lJY_xBV7rGrbUSvkZQ">
    <img src="https://img.shields.io/youtube/channel/views/UCach3lJY_xBV7rGrbUSvkZQ?style=social" />
  </a>
  <a href="https://reddit.com/r/netmaker">
    <img src="https://img.shields.io/reddit/subreddit-subscribers/netmaker?label=%2Fr%2Fnetmaker&style=social" />
  </a>  
  <a href="https://discord.gg/zRb9Vfhk8A">
    <img src="https://img.shields.io/discord/825071750290210916?color=%09%237289da&label=chat" />
  </a> 
</p>

# WireGuard<sup>®</sup> automation from homelab to enterprise

| Create                                    | Manage                                  | Automate                                |
|-------------------------------------------|-----------------------------------------|-----------------------------------------|
| :heavy_check_mark: WireGuard Networks     | :heavy_check_mark: Admin UI             | :heavy_check_mark: Linux                |
| :heavy_check_mark: Remote Access Gateways | :heavy_check_mark: OAuth                | :heavy_check_mark: Docker              |
| :heavy_check_mark: Mesh VPNs              | :heavy_check_mark: Private DNS          | :heavy_check_mark: Mac                  |
| :heavy_check_mark: Site-to-Site           | :heavy_check_mark: Access Control Lists | :heavy_check_mark: Windows              |

# Try Netmaker SaaS  

If you're looking for a managed service, you can get started with just a few clicks, visit [netmaker.io](https://account.netmaker.io) to create your netmaker server.  

# Self-Hosted Open Source Quick Start  

These are the instructions for deploying a Netmaker server on your cloud VM as quickly as possible. For more detailed instructions, visit the [Install Docs](https://docs.netmaker.io/docs/server-installation/quick-install#quick-install-script).  

1. Get a cloud VM with Ubuntu 24.04 and a static public IP.
2. Allow inbound traffic on port 443,51821 TCP and UDP to the VM firewall in cloud security settings, and for simplicity, allow outbound on All TCP and All UDP.
3. (recommended) Prepare DNS - Set a wildcard subdomain in your DNS settings for Netmaker, e.g. *.netmaker.example.com, which points to your VM's public IP.
4. Run the script to setup open source version of Netmaker: 

`sudo wget -qO /root/nm-quick.sh https://raw.githubusercontent.com/gravitl/netmaker/master/scripts/nm-quick.sh && sudo chmod +x /root/nm-quick.sh && sudo /root/nm-quick.sh`

**<pre>To Install Self-Hosted PRO Version - https://docs.netmaker.io/docs/server-installation/netmaker-professional-setup</pre>** 



<p float="left" align="middle">
<img src="https://raw.githubusercontent.com/gravitl/netmaker-docs/master/images/netmaker-github/readme.gif" />
</p>

After installing Netmaker, check out the [Walkthrough](https://itnext.io/getting-started-with-netmaker-a-wireguard-virtual-networking-platform-3d563fbd87f0) and [Getting Started](https://docs.netmaker.io/docs/getting-started) guides to learn more about configuring networks. Or, check out some of our other [Tutorials](https://www.netmaker.io/blog) for different use cases, including Kubernetes.

# Get Support

- [Discord](https://discord.gg/zRb9Vfhk8A)

- [Reddit](https://reddit.com/r/netmaker)

- [Learning Resources](https://netmaker.io/blog)

# Why Netmaker + WireGuard?

- Netmaker automates virtual networks between data centres, clouds, and edge devices, so you don't have to.

- Kernel WireGuard offers maximum speed, performance, and security. 

- Netmaker is built to scale from small businesses to enterprises. 

- Netmaker with WireGuard can be highly customized for peer-to-peer, site-to-site, Kubernetes, and more.

# Community Projects

- [Netmaker + Traefik Proxy](https://github.com/bsherman/netmaker-traefik)

- [OpenWRT Netclient Packager](https://github.com/sbilly/netmaker-openwrt)

- [Golang GUI](https://github.com/mattkasun/netmaker-gui)

- [CoreDNS Plugin](https://github.com/gravitl/netmaker-coredns-plugin)

- [Multi-Cluster K8S Plugin](https://github.com/gravitl/netmak8s)

- [Terraform Provider](https://github.com/madacluster/netmaker-terraform-provider)

- [VyOS Integration](https://github.com/kylechase/vyos-netmaker)

- [Netmaker K3S](https://github.com/geragcp/netmaker-k3s)

- [Run Netmaker + Netclient with Podman](https://github.com/agorgl/nm-setup)

## Disclaimer
 [WireGuard](https://wireguard.com/) is a registered trademark of Jason A. Donenfeld.

## License

Netmaker's source code and all artifacts in this repository are freely available.
All content that resides under the "pro/" directory of this repository, if that
directory exists, is licensed under the license defined in "pro/LICENSE".
All third party components incorporated into the Netmaker Software are licensed
under the original license provided by the owner of the applicable component.
Content outside of the above mentioned directories or restrictions above is
available under the "Apache Version 2.0" license as defined below.
All details for the licenses used can be found here: [LICENSE.md](./LICENSE.md).
