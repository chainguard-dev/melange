#!/bin/bash
# Script to generate test binaries for golden tests

set -e

# Build Go binary
echo "Building Go test binary..."
cd go-module
go mod download
go build -o test-binary main.go
cd ..

echo "Test binary generated successfully"