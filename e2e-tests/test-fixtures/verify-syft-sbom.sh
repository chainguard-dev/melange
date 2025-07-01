#!/bin/bash
# Verify that SBOM contains Syft-detected packages when --scan-contents is used

set -e

PACKAGE_NAME="syft-sbom-scan-test"
SBOM_FILE="packages/x86_64/${PACKAGE_NAME}-1.0.0-r0.apk"
TEMP_DIR=$(mktemp -d)

# Extract the APK
tar -xf "$SBOM_FILE" -C "$TEMP_DIR" 2>/dev/null || true

# Find the SBOM JSON file
SBOM_JSON=$(find "$TEMP_DIR" -name "*.spdx.json" -type f | head -1)

if [ -z "$SBOM_JSON" ]; then
    echo "ERROR: No SBOM JSON file found in package"
    rm -rf "$TEMP_DIR"
    exit 1
fi

echo "Found SBOM file: $SBOM_JSON"

# Check if Syft-detected packages are present
# We should find Go modules like github.com/spf13/cobra
if grep -q "github.com/spf13/cobra" "$SBOM_JSON"; then
    echo "✓ Found Syft-detected Go module: github.com/spf13/cobra"
else
    echo "✗ Did not find expected Go module in SBOM"
    FAILED=1
fi

# Check for Python packages
if grep -q "requests.*2.31.0" "$SBOM_JSON"; then
    echo "✓ Found Syft-detected Python package: requests"
else
    echo "✗ Did not find expected Python package in SBOM"
    FAILED=1
fi

# Check for Node.js packages
if grep -q "express.*4.18.2" "$SBOM_JSON"; then
    echo "✓ Found Syft-detected Node.js package: express"
else
    echo "✗ Did not find expected Node.js package in SBOM"
    FAILED=1
fi

# Check for CONTAINS relationships
CONTAINS_COUNT=$(grep -c '"typeRelationship":"CONTAINS"' "$SBOM_JSON" || true)
echo "Found $CONTAINS_COUNT CONTAINS relationships in SBOM"

if [ "$CONTAINS_COUNT" -gt 0 ]; then
    echo "✓ SBOM contains relationship data from Syft"
else
    echo "✗ No CONTAINS relationships found"
    FAILED=1
fi

# Cleanup
rm -rf "$TEMP_DIR"

if [ -n "$FAILED" ]; then
    echo "SBOM verification failed!"
    exit 1
fi

echo "SBOM verification passed!"