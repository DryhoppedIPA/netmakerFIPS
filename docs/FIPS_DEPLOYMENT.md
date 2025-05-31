# FIPS-Compliant Netmaker Deployment

This deployment uses FIPS 140-3 validated cryptography and is **incompatible** with standard WireGuard networks.

## Key Differences

| Feature | Standard WireGuard | FIPS WireGuard |
|---------|-------------------|----------------|
| Key Algorithm | Curve25519 | NIST P-256 |
| Key Size | 32 bytes | 65 bytes |
| Base64 Length | 44 chars | 88-89 chars |
| Encryption | ChaCha20-Poly1305 | AES-GCM |
| Hash | BLAKE2s | SHA-256 |

## Generating FIPS-Compliant Keys

Use the wolfSSL-patched WireGuard tools:
```bash
# Generate private key
wg genkey > private.key

# Derive public key
wg pubkey < private.key > public.key

# View the key (should be 88-89 characters)
cat public.key
```

## Example Configuration

```ini
[Interface]
PrivateKey = <88-character-base64-P256-private-key>
Address = 10.0.0.1/24

[Peer]
PublicKey = <88-character-base64-P256-public-key>
AllowedIPs = 10.0.0.2/32
Endpoint = peer.example.com:51820
```

## API Changes

### Public Key Format
All public keys in API requests must be base64-encoded P-256 keys (88-89 characters).

Example valid key:
```
BEWanDenKpBCvt5bajVS5p3WbSfL0SoD3Dt1nNekYk3xK6DoncgtcZXxFtKFUH7+VDPSZQRpTnm+LlUJo2ewCYI=
```

### Node Creation
```json
{
  "id": "node1",
  "publickey": "BEWanDenKpBCvt5bajVS5p3WbSfL0SoD3Dt1nNekYk3xK6DoncgtcZXxFtKFUH7+VDPSZQRpTnm+LlUJo2ewCYI=",
  "network": "mynetwork"
}
```

## Important Notes

1. **No Mixed Networks**: FIPS and non-FIPS nodes cannot communicate
2. **Key Validation**: All keys are validated to ensure they are valid P-256 points
3. **Database Schema**: Public key fields support up to 89 characters
4. **WireGuard Binary**: Must use wolfSSL-patched WireGuard with FIPS support 