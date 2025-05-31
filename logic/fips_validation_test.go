package logic

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestValidatePublicKey(t *testing.T) {
	cases := []struct {
		name    string
		keyFunc func() string
		wantErr bool
		errPart string
	}{
		{
			name: "Valid P-256",
			keyFunc: func() string {
				// Generate a "dummy" key via Go's crypto for test purposes
				priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				//lint:ignore SA1019 We are aware this is deprecated and will be replaced by wolfCrypt FIPS API for testing as well.
				raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
				return base64.StdEncoding.EncodeToString(raw)
			},
			wantErr: false,
		},
		{
			name:    "Invalid Base64",
			keyFunc: func() string { return "!!notbase64!!" },
			wantErr: true,
			errPart: "invalid base64",
		},
		{
			name: "Wrong Length (64 bytes)",
			keyFunc: func() string {
				junk := make([]byte, 64)
				return base64.StdEncoding.EncodeToString(junk)
			},
			wantErr: true,
			errPart: "invalid key length",
		},
		{
			name: "Wrong Prefix (0x05)",
			keyFunc: func() string {
				data := make([]byte, 65)
				data[0] = 0x05
				return base64.StdEncoding.EncodeToString(data)
			},
			wantErr: true,
			errPart: "invalid key prefix",
		},
		{
			name: "Off Curve Point",
			keyFunc: func() string {
				data := make([]byte, 65)
				data[0] = 0x04
				for i := 1; i < 65; i++ {
					data[i] = 0xFF
				}
				return base64.StdEncoding.EncodeToString(data)
			},
			wantErr: true,
			errPart: "point not on the curve",
		},
		{
			name:    "Empty String",
			keyFunc: func() string { return "" },
			wantErr: true,
			errPart: "invalid base64",
		},
		{
			name: "Curve25519 Length (32 bytes)",
			keyFunc: func() string {
				junk := make([]byte, 32)
				return base64.StdEncoding.EncodeToString(junk)
			},
			wantErr: true,
			errPart: "invalid key length",
		},
		{
			name:    "Actual Curve25519 Key",
			keyFunc: func() string { return "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=" },
			wantErr: true,
			errPart: "invalid key length",
		},
		{
			name: "Compressed P-256 (33 bytes)",
			keyFunc: func() string {
				data := make([]byte, 33)
				data[0] = 0x02
				return base64.StdEncoding.EncodeToString(data)
			},
			wantErr: true,
			errPart: "invalid key length",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyB64 := tc.keyFunc()
			err := ValidatePublicKey(keyB64)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				} else if tc.errPart != "" && !bytes.Contains([]byte(err.Error()), []byte(tc.errPart)) {
					t.Errorf("error = %q; want it to contain %q", err.Error(), tc.errPart)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGenerateP256KeyPair_Serialization(t *testing.T) {
	// This test demonstrates round-tripping via Go's ecdsa for illustration.
	priv, pubB64, err := GenerateP256KeyPair()
	if err != nil {
		t.Fatalf("GenerateP256KeyPair error: %v", err)
	}
	if err := ValidatePublicKey(pubB64); err != nil {
		t.Errorf("Generated public key failed validation: %v", err)
	}
	privB64, serr := SerializeP256PrivateKey(priv)
	if serr != nil {
		t.Fatalf("SerializeP256PrivateKey error: %v", serr)
	}
	// Deserialize and confirm it matches the original public key
	desPriv, derr := DeserializeP256PrivateKey(privB64)
	if derr != nil {
		t.Fatalf("DeserializeP256PrivateKey error: %v", derr)
	}
	//lint:ignore SA1019 We are aware this is deprecated and will be replaced by wolfCrypt FIPS API for testing as well.
	rePub := elliptic.Marshal(elliptic.P256(), desPriv.PublicKey.X, desPriv.PublicKey.Y)
	rePubB64 := base64.StdEncoding.EncodeToString(rePub)
	if rePubB64 != pubB64 {
		t.Errorf("Round-trip public key mismatch: got %s, want %s", rePubB64, pubB64)
	}
}
