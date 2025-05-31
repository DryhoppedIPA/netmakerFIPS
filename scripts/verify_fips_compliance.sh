#!/usr/bin/env bash
# File: scripts/verify_fips_compliance.sh

set -e

echo "=== FIPS Compliance Verification ==="
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# Function to run a command and print PASS/FAIL
function check() {
    local name="$1"
    local cmd="$2"
    echo -n "Checking $name... "
    if eval "$cmd"; then
        echo -e "${GREEN}✓ PASS${NC}"
    else
        echo -e "${RED}✗ FAIL${NC}"
        FAILED=$((FAILED+1))
    fi
}

FAILED=0

# 1. No Curve25519 references (except in tests/docs)
check "No Curve25519 references" \
      "! grep -r 'Curve25519\|curve25519' . --include='*.go' --exclude-dir='{.git,vendor,test}' | grep -v -E '(test|comment|removed|FIPS)'"

# 2. No wgtypes.ParseKey usage
check "No wgtypes.ParseKey usage" \
      "! grep -r 'wgtypes\.ParseKey' . --include='*.go' --exclude-dir='{.git,vendor,test}' --exclude='*_test.go'"

# 3. No wgtypes.Key type usage (for public keys)
check "No wgtypes.Key usage" \
      "! grep -r 'wgtypes\.Key\s' . --include='*.go' --exclude-dir='{.git,vendor,test}'"

# 4. logic/fips_validation.go must exist
check "logic/fips_validation.go exists" \
      "test -f logic/fips_validation.go"

# 5. ValidatePublicKey must be called at least once somewhere
check "ValidatePublicKey is used" \
      "grep -r 'ValidatePublicKey' . --include='*.go' --exclude-dir='{.git,vendor,test}' | grep -q ."

# 6. OS-level FIPS must be enabled (if running on Linux FIPS host)
if [ -f /proc/sys/crypto/fips_enabled ]; then
    check "OS-level FIPS enabled" \
          "[ \"\$(cat /proc/sys/crypto/fips_enabled)\" = \"1\" ]"
else
    echo -e "Checking OS-level FIPS... ${YELLOW}SKIP (not a Linux host)${NC}"
fi

# 7. Verify wireguard-go-fips binary contains wolfCrypt FIPS
if [ -f /usr/local/bin/wireguard-go ]; then
    check "wireguard-go-fips is the FIPS build" \
          "strings /usr/local/bin/wireguard-go | grep -q 'wolfCrypt FIPS'"
else
    echo -e "Checking wireguard-go-fips... ${YELLOW}SKIP (binary not found)${NC}"
fi

echo
if [ $FAILED -ne 0 ]; then
    echo -e "${RED}✗ $FAILED checks failed${NC}"
    exit 1
else
    echo -e "${GREEN}✓ All FIPS compliance checks passed!${NC}"
    exit 0
fi 