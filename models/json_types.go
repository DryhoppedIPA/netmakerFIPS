// File: models/json_types.go
package models

import (
    "encoding/json"
    "fmt"
    "net"
    "time"
)

// UDPAddrString wraps net.UDPAddr so that JSON is a quoted "IP:Port" string.
type UDPAddrString struct {
    *net.UDPAddr
}

// MarshalJSON renders the UDPAddr as `"1.2.3.4:51820"` (quoted string).
func (u UDPAddrString) MarshalJSON() ([]byte, error) {
    if u.UDPAddr == nil {
        return []byte(`""`), nil
    }
    s := u.String() // "IP:Port"
    return json.Marshal(s)
}

// UnmarshalJSON parses a JSON string "IP:Port" into a UDPAddrString.
func (u *UDPAddrString) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    if s == "" {
        u.UDPAddr = nil
        return nil
    }
    addr, err := net.ResolveUDPAddr("udp", s)
    if err != nil {
        return fmt.Errorf("invalid UDP address %q: %w", s, err)
    }
    u.UDPAddr = addr
    return nil
}

// DurationSeconds wraps time.Duration so that JSON is a quoted "<n>s" string.
type DurationSeconds struct {
    time.Duration
}

// MarshalJSON outputs JSON as a quoted string like "25s".
func (d DurationSeconds) MarshalJSON() ([]byte, error) {
    if d.Duration == 0 {
        return []byte(`""`), nil
    }
    s := fmt.Sprintf("%ds", int(d.Duration.Seconds()))
    return json.Marshal(s)
}

// UnmarshalJSON parses a JSON string like "25s" or empty into DurationSeconds.
func (d *DurationSeconds) UnmarshalJSON(data []byte) error {
    var s string
    if err := json.Unmarshal(data, &s); err != nil {
        return err
    }
    if s == "" {
        d.Duration = 0
        return nil
    }
    var secs int
    if _, err := fmt.Sscanf(s, "%ds", &secs); err != nil {
        return fmt.Errorf("invalid duration %q: %w", s, err)
    }
    d.Duration = time.Duration(secs) * time.Second
    return nil
} 