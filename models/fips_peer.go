// File: models/fips_peer.go
package models

// FIPSPeerConfig is the JSON format that WireGuard-GO expects.
// We rely on UDPAddrString and DurationSeconds for correct JSON.
type FIPSPeerConfig struct {
	PublicKey                   string          `json:"publickey"` // Base64-encoded P-256
	Remove                      bool            `json:"remove,omitempty"`
	Endpoint                    UDPAddrString   `json:"endpoint,omitempty"`            // "IP:Port"
	PersistentKeepaliveInterval DurationSeconds `json:"persistentkeepalive,omitempty"` // "Ns"
	ReplaceAllowedIPs           bool            `json:"replaceallowedips,omitempty"`
	AllowedIPs                  []string        `json:"allowedips,omitempty"` // e.g. ["10.0.0.2/32"]
}
