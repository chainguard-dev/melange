#!/bin/bash
# Helper script to update the Syft SBOM golden file

set -e

cd "$(dirname "$0")"

echo "Building package with --scan-contents to generate new SBOM..."
go run ../ build --arch=x86_64 --source-dir=./test-fixtures --runner=docker \
  syft-sbom-scan-build-test.yaml --signing-key=local-melange.rsa --scan-contents \
  --keyring-append=local-melange.rsa.pub --repository-append=packages \
  --repository-append=https://packages.wolfi.dev/os \
  --keyring-append=https://packages.wolfi.dev/os/wolfi-signing.rsa.pub

echo "Extracting and normalizing SBOM from built package..."
tar -xOf packages/x86_64/syft-sbom-scan-test-1.0.0-r0.apk \
  var/lib/db/sbom/syft-sbom-scan-test-1.0.0-r0.spdx.json | \
  ./test-fixtures/normalize-sbom.sh \
  >test-fixtures/syft-sbom-scan-test-with-scan.golden.json

echo "✓ Golden file updated (normalized): test-fixtures/syft-sbom-scan-test-with-scan.golden.json"
echo ""
echo "Run the test to verify:"
echo "  ./run-tests syft-sbom-scan-build-test.yaml"
