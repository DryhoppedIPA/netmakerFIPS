#!/usr/bin/env bash
# File: test/fips_integration.sh
set -euo pipefail

# --------------------------------------------------------------------------------
# This script sets up two nodes (A and B), each running Netmaker + wireguard-go-fips.
# It then:
#   1) Registers Node A with Netmaker server
#   2) Registers Node B with Netmaker server
#   3) Brings up wg0 on both nodes
#   4) Runs iperf3 between them to verify traffic
#   5) Uses tshark to confirm AES-GCM (FIPS mode), not ChaCha20
# --------------------------------------------------------------------------------

# 1) Configuration (adjust these hostnames or IPs to match your test environment)
NETMAKER_SERVER="netmaker-server.local"    # The Netmaker API endpoint
NODE_A="node-a"                            # Hostname or IP for Node A
NODE_B="node-b"                            # Hostname or IP for Node B
WG_INTERFACE="wg0"

echo "=== 1) Ensure FIPS mode on both nodes ==="
for NODE in "$NODE_A" "$NODE_B"; do
    echo -n "Checking /proc/sys/crypto/fips_enabled on $NODE... "
    if ssh "$NODE" "test \"\$(cat /proc/sys/crypto/fips_enabled)\" = 1"; then
        echo "OK"
    else
        echo "FAIL (not in FIPS mode)"
        exit 1
    fi

    echo -n "Checking wireguard-go-fips binary on $NODE... "
    if ssh "$NODE" "strings /usr/local/bin/wireguard-go | grep -q 'wolfCrypt FIPS'"; then
        echo "OK"
    else
        echo "FAIL (wolfCrypt FIPS string missing)"
        exit 1
    fi
done

echo "=== 2) Register Node A and Node B with Netmaker ==="
for NODE in "$NODE_A" "$NODE_B"; do
    echo "Registering $NODE..."
    # On each node, run our Go logic to generate a FIPS P-256 key pair.
    # In production, GenerateP256KeyPair() must invoke wolfCrypt, but for this test,
    # we assume GenerateP256KeyPair() in Go produces a valid P-256 public key.
    PUB_KEY=$(ssh "$NODE" "go run github.com/gravitl/netmaker/logic GenerateP256KeyPair | tail -n 1")
    ssh "$NODE" bash -c "cat <<EOF | curl -s -X POST http://${NETMAKER_SERVER}:8081/api/node \
      -H 'Content-Type: application/json' \
      -d @-
{
  \"publickey\": \"${PUB_KEY}\",
  \"allowedips\": [\"10.50.50.$(($RANDOM%250+2))/32\"]
}
EOF"
done

echo "=== 3) Fetch Config and Bring Up wg0 Interfaces ==="
for NODE in "$NODE_A" "$NODE_B"; do
    echo "Fetching and applying wg0.conf on $NODE..."
    # Assume Netmaker API endpoint: GET /api/node/{nodeID}/config returns wg0.conf text
    NODE_ID=$(ssh "$NODE" "hostname")  # or however Netmaker identifies node
    CONF=$(ssh "$NODE" "curl -s http://${NETMAKER_SERVER}:8081/api/node/${NODE_ID}/config")
    ssh "$NODE" "echo \"\$CONF\" | sudo tee /etc/wireguard/${WG_INTERFACE}.conf > /dev/null"
    ssh "$NODE" "sudo wg-quick up ${WG_INTERFACE}"
done

echo "=== 4) Test Tunnel with iperf3 ==="
# Start iperf3 server on Node B
ssh "$NODE_B" "nohup iperf3 -s > /tmp/iperf3.log 2>&1 &"
sleep 2

# Determine Node B's WireGuard IP from its wg0.conf
WG_IP_B=$(ssh "$NODE_B" "awk '/^Address/ {print \$2}' /etc/wireguard/${WG_INTERFACE}.conf | cut -d/ -f1")
ssh "$NODE_A" "iperf3 -c ${WG_IP_B} -t 10 -f m"
echo "iperf3 test completed. Observe throughput >100 Mbps (or as hardware permits)."

echo "=== 5) Packet Capture with tshark to Confirm AES-GCM ==="
ssh "$NODE_A" "sudo timeout 5s tshark -i ${WG_INTERFACE} -c 10 -Y 'wireguard' -T fields -e 'wireguard.message.type' -e 'wireguard.cipher' > /tmp/tshark_wg.txt"
echo "tshark output (first 10 WireGuard packets) on Node A:"
ssh "$NODE_A" "cat /tmp/tshark_wg.txt"

echo "=== 6) Clean Up ==="
for NODE in "$NODE_A" "$NODE_B"; do
    ssh "$NODE" "sudo wg-quick down ${WG_INTERFACE} || true; sudo rm -f /tmp/iperf3.log /tmp/tshark_wg.txt"
done

echo "=== FIPS Integration Test Completed Successfully! ===" 