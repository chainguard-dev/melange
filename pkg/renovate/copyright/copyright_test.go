// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package copyright

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
)

func TestCopyright_update(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	detectedLicenses := []license.License{
		{
			Name:       "Apache-2.0",
			Source:     "LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "MIT",
			Source:     "internal/COPYING",
			Confidence: 1.0,
		},
		{
			Name:       "GPL-3.0",
			Source:     "internal/LICENSE",
			Confidence: 0.2,
		},
		{
			Name:       "NOASSERTION",
			Source:     "docs/COPYING",
			Confidence: 0.0,
		},
	}

	diffs := []license.LicenseDiff{
		{
			Path:   "LICENSE",
			Is:     "GPL-2.0",
			Should: "Apache-2.0",
		},
	}

	// Copy the test data file to the temp directory
	src := filepath.Join("testdata", "nolicense.yaml")
	testFile := filepath.Join(dir, "nolicense.yaml")
	input, err := os.ReadFile(src)
	assert.NoError(t, err)

	err = os.WriteFile(testFile, input, 0o644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)
	assert.Contains(t, string(resultData), "license: Apache-2.0")
	assert.Contains(t, string(resultData), "license: MIT")
	assert.NotContains(t, string(resultData), "license: Not-Applicable")
	assert.NotContains(t, string(resultData), "license: GPL-3.0")
	assert.NotContains(t, string(resultData), "license: NOASSERTION")
}

func TestCopyright_noDiffs(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	detectedLicenses := []license.License{
		{
			Name:       "Invalid",
			Source:     "LICENSE",
			Confidence: 1.0,
		},
	}

	diffs := []license.LicenseDiff{}

	// Copy the test data file to the temp directory
	src := filepath.Join("testdata", "nolicense.yaml")
	testFile := filepath.Join(dir, "nolicense.yaml")
	input, err := os.ReadFile(src)
	assert.NoError(t, err)

	err = os.WriteFile(testFile, input, 0o644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	// The diffs is empty, so the renovator should not modify the file
	// Let's make sure that's the case by checking that the file still contains the original license
	assert.Contains(t, string(resultData), "license: Not-Applicable")
	assert.NotContains(t, string(resultData), "license: Invalid")
}

func TestCopyright_updateSimple(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	detectedLicenses := []license.License{
		{
			Name:       "Apache-2.0",
			Source:     "LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "MIT",
			Source:     "internal/COPYING",
			Confidence: 1.0,
		},
		{
			Name:       "Apache-2.0",
			Source:     "vendor/foo/LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "GPL-3.0",
			Source:     "internal/LICENSE",
			Confidence: 0.2,
		},
	}

	diffs := []license.LicenseDiff{
		{
			Path:   "LICENSE",
			Is:     "GPL-2.0",
			Should: "Apache-2.0",
		},
	}

	// Copy the test data file to the temp directory
	src := filepath.Join("testdata", "nolicense.yaml")
	testFile := filepath.Join(dir, "nolicense.yaml")
	input, err := os.ReadFile(src)
	assert.NoError(t, err)

	err = os.WriteFile(testFile, input, 0o644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithFormat("simple"))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	// The copyright field should contain a single license entry with both licenses joined by " AND "
	result := string(resultData)
	assert.Contains(t, result, "license: Apache-2.0 AND MIT")
	assert.NotContains(t, result, "GPL-3.0")
	assert.NotContains(t, result, "NOASSERTION")
}
