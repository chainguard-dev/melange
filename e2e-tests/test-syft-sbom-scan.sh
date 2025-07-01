#!/bin/bash
# E2E test for Syft SBOM scanning feature

set -e

MELANGE=${MELANGE:-melange}
if [ "$MELANGE" = "melange" ]; then
    MELANGE=$(which melange)
fi

echo "Testing Syft SBOM scanning with melange from $MELANGE"

# Create signing key if needed
key="local-melange.rsa"
if [ -f "$key" -a -f "$key.pub" ]; then
    echo "using existing $key"
else
    $MELANGE keygen "$key" ||
        { echo "failed to create local-melange signing key"; exit 1; }
fi

# Clean up any previous runs
rm -rf packages/

echo "=== Test 1: Build WITHOUT --scan-contents (baseline) ==="
$MELANGE build \
    --arch=x86_64 \
    --source-dir=./test-fixtures \
    --runner=qemu \
    --signing-key="$PWD/$key" \
    --keyring-append="$PWD/$key.pub" \
    --repository-append="$PWD/packages" \
    --repository-append="https://packages.wolfi.dev/os" \
    --keyring-append="https://packages.wolfi.dev/os/wolfi-signing.rsa.pub" \
    syft-sbom-scan-test.yaml

# Extract and check baseline SBOM
echo "Checking baseline SBOM (without Syft scanning)..."
TEMP_DIR=$(mktemp -d)
tar -xf "packages/x86_64/syft-sbom-scan-test-1.0.0-r0.apk" -C "$TEMP_DIR" 2>/dev/null || true
SBOM_JSON=$(find "$TEMP_DIR" -name "*.spdx.json" -type f | head -1)

if grep -q "github.com/spf13/cobra" "$SBOM_JSON" 2>/dev/null; then
    echo "ERROR: Baseline SBOM should NOT contain Syft-detected packages!"
    rm -rf "$TEMP_DIR"
    exit 1
fi
echo "✓ Baseline SBOM does not contain Syft-detected packages (as expected)"
rm -rf "$TEMP_DIR"

# Clean up for second run
rm -rf packages/

echo -e "\n=== Test 2: Build WITH --scan-contents ==="
$MELANGE build \
    --arch=x86_64 \
    --source-dir=./test-fixtures \
    --runner=qemu \
    --signing-key="$PWD/$key" \
    --keyring-append="$PWD/$key.pub" \
    --repository-append="$PWD/packages" \
    --repository-append="https://packages.wolfi.dev/os" \
    --keyring-append="https://packages.wolfi.dev/os/wolfi-signing.rsa.pub" \
    --scan-contents \
    syft-sbom-scan-test.yaml

# Verify the SBOM contains Syft-detected packages
echo -e "\nVerifying SBOM with Syft scanning..."
./test-fixtures/verify-syft-sbom.sh

echo -e "\n=== All tests passed! ==="