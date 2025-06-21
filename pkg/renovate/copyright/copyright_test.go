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

	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/renovate"
	"github.com/stretchr/testify/assert"
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

	err = os.WriteFile(testFile, input, 0644)
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

	err = os.WriteFile(testFile, input, 0644)
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

func TestCopyright_structuredMode_singleDirectory(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	// Two licenses in the same directory (root)
	detectedLicenses := []license.License{
		{
			Name:       "Apache-2.0",
			Source:     "LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "MIT",
			Source:     "COPYING",
			Confidence: 1.0,
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

	err = os.WriteFile(testFile, input, 0644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(true))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	// With structured mode and multiple licenses in same directory, should create OR group
	assert.Contains(t, string(resultData), "operator: OR")
	assert.Contains(t, string(resultData), "license: Apache-2.0")
	assert.Contains(t, string(resultData), "license: MIT")
	assert.NotContains(t, string(resultData), "license: Not-Applicable")
}

func TestCopyright_structuredMode_multipleDirectories(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	// Licenses in different directories
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
			Source:     "vendor/third-party/LICENSE",
			Confidence: 1.0,
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

	err = os.WriteFile(testFile, input, 0644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(true))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	// With structured mode and multiple directories, should create AND group at top level
	assert.Contains(t, string(resultData), "operator: AND")
	assert.Contains(t, string(resultData), "license: Apache-2.0")
	assert.Contains(t, string(resultData), "license: MIT")
	assert.Contains(t, string(resultData), "license: GPL-3.0")
	assert.NotContains(t, string(resultData), "license: Not-Applicable")
}

func TestCopyright_structuredMode_complexHierarchy(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	// Complex structure: multiple licenses in some directories, single in others
	detectedLicenses := []license.License{
		{
			Name:       "Apache-2.0",
			Source:     "LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "MIT",
			Source:     "LICENSE-MIT",
			Confidence: 1.0,
		},
		{
			Name:       "GPL-3.0",
			Source:     "internal/LICENSE",
			Confidence: 1.0,
		},
		{
			Name:       "BSD-3-Clause",
			Source:     "internal/COPYING",
			Confidence: 1.0,
		},
		{
			Name:       "ISC",
			Source:     "vendor/LICENSE",
			Confidence: 1.0,
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

	err = os.WriteFile(testFile, input, 0644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(true))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	result := string(resultData)

	// Should have top-level AND for multiple directories
	assert.Contains(t, result, "operator: AND")
	// Should have OR for internal directory (GPL-3.0 and BSD-3-Clause)
	assert.Contains(t, result, "operator: OR")
	// All licenses should be present
	assert.Contains(t, result, "license: Apache-2.0")
	assert.Contains(t, result, "license: MIT")
	assert.Contains(t, result, "license: GPL-3.0")
	assert.Contains(t, result, "license: BSD-3-Clause")
	assert.Contains(t, result, "license: ISC")
	assert.NotContains(t, result, "license: Not-Applicable")
}

func TestCopyright_structuredMode_singleLicense(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	// Single license - should use simple format even in structured mode
	detectedLicenses := []license.License{
		{
			Name:       "Apache-2.0",
			Source:     "LICENSE",
			Confidence: 1.0,
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

	err = os.WriteFile(testFile, input, 0644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFile))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(true))

	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	resultData, err := os.ReadFile(testFile)
	assert.NoError(t, err)

	result := string(resultData)

	// Should use simple format for single license
	assert.Contains(t, result, "license: Apache-2.0")
	assert.NotContains(t, result, "operator:")
	assert.NotContains(t, result, "license: Not-Applicable")
}

func TestCopyright_flatVsStructured(t *testing.T) {
	dir := t.TempDir()
	ctx := slogtest.Context(t)

	// Same license set for both tests
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
	}

	diffs := []license.LicenseDiff{
		{
			Path:   "LICENSE",
			Is:     "GPL-2.0",
			Should: "Apache-2.0",
		},
	}

	// Test flat mode
	src := filepath.Join("testdata", "nolicense.yaml")
	testFileFiat := filepath.Join(dir, "flat.yaml")
	input, err := os.ReadFile(src)
	assert.NoError(t, err)
	err = os.WriteFile(testFileFiat, input, 0644)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(testFileFiat))
	assert.NoError(t, err)

	copyrightRenovator := New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(false))
	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	flatResult, err := os.ReadFile(testFileFiat)
	assert.NoError(t, err)

	// Test structured mode
	testFileStructured := filepath.Join(dir, "structured.yaml")
	err = os.WriteFile(testFileStructured, input, 0644)
	assert.NoError(t, err)

	rctx, err = renovate.New(renovate.WithConfig(testFileStructured))
	assert.NoError(t, err)

	copyrightRenovator = New(ctx, WithLicenses(detectedLicenses), WithDiffs(diffs), WithStructured(true))
	err = rctx.Renovate(slogtest.Context(t), copyrightRenovator)
	assert.NoError(t, err)

	structuredResult, err := os.ReadFile(testFileStructured)
	assert.NoError(t, err)

	// Both should contain the licenses but structured differently
	flatStr := string(flatResult)
	structuredStr := string(structuredResult)

	// Both should have the licenses
	assert.Contains(t, flatStr, "license: Apache-2.0")
	assert.Contains(t, flatStr, "license: MIT")
	assert.Contains(t, structuredStr, "license: Apache-2.0")
	assert.Contains(t, structuredStr, "license: MIT")

	// Flat should not have operators
	assert.NotContains(t, flatStr, "operator:")

	// Structured should have AND operator (different directories)
	assert.Contains(t, structuredStr, "operator: AND")
}
