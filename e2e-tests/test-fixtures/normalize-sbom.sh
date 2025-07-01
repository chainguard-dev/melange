#!/bin/sh
# Normalize an SBOM by replacing expected variable content with placeholders
# This allows golden file comparisons to ignore expected differences

# Usage: normalize-sbom.sh < input.json > output.json
#    or: normalize-sbom.sh input.json > output.json

if [ $# -eq 1 ]; then
    # Read from file
    input_file="$1"
    cat "$input_file"
else
    # Read from stdin
    cat
fi | sed -E \
    -e 's/"Tool: melange \([^)]+\)"/"Tool: melange (VERSION)"/' \
    -e 's/"versionInfo": "[a-f0-9]{40}"/"versionInfo": "GITHASH"/' \
    -e 's/SPDXRef-Package-syft-sbom-scan-build-test\.yaml-[a-f0-9]{40}/SPDXRef-Package-syft-sbom-scan-build-test.yaml-GITHASH/g' \
    -e 's/@[a-f0-9]{40}#/@GITHASH#/g'