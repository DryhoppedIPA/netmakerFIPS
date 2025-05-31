// File: metrics/fips_metrics.go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
)

var (
    // KeysValidated counts how many public keys we've validated (with labels "valid" or "invalid").
    KeysValidated = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "netmaker_fips_keys_validated_total",
            Help: "Total number of public keys validated (tagged by status: valid or invalid).",
        },
        []string{"status"},
    )
    // HandshakeFailures counts how many WireGuard handshake failures we've detected.
    HandshakeFailures = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "netmaker_fips_handshake_failures_total",
            Help: "Total number of WireGuard handshake failures detected in FIPS mode.",
        },
    )
)

func init() {
    prometheus.MustRegister(KeysValidated, HandshakeFailures)
} 