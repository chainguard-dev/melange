#!/usr/bin/env bash

# Copyright 2023 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

if [[ ! -f melange.images ]]; then
    echo "melange.images not found"
    exit 1
fi

echo "Signing melange images using Keyless..."

readarray -t melange < <(cat melange.images || true)
cosign sign --yes --timeout 5m "${melange[@]}"
