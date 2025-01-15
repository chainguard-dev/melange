// Copyright 2022 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build e2e
// +build e2e

package python

import (
	"fmt"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
)

// This test downloads 10MB from files.pythonhosted.org (twice).
// I am not in a position to untangle it, so we're going to gate this behind an e2e build tag that only runs in CI.
func TestGenerateManifest(t *testing.T) {
	ctx := slogtest.Context(t)

	for i := range versions {
		pythonctxs, err := SetupContext(versions[i])
		assert.NoError(t, err)

		// botocore ctx
		pythonctx := pythonctxs[0]
		// Add additionalReposities and additionalKeyrings
		pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
		pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}

		got, err := pythonctx.generateManifest(ctx, pythonctx.Package, pythonctx.PackageVersion, nil, nil)
		assert.NoError(t, err)

		// Check Package
		assert.Equal(t, got.Package.Name, "py"+versions[i]+"-botocore")
		assert.Equal(t, got.Package.Version, "1.29.78")
		assert.EqualValues(t, got.Package.Epoch, 0)
		assert.Equal(t, got.Package.Description, "Low-level, data-driven core of boto 3.")
		assert.Equal(t, []string(nil), got.Package.Dependencies.Runtime)
		assert.Equal(t, "0", got.Package.Dependencies.ProviderPriority)

		// Check Package.Copyright
		assert.Equal(t, len(got.Package.Copyright), 1)
		assert.Equal(t, got.Package.Copyright[0].License, "Apache License 2.0")

		// Check Environment
		assert.Equal(t, got.Environment.Contents.Packages, []string{
			"build-base",
			"busybox",
			"ca-certificates-bundle",
			"py3-supported-build-base-dev",
			"wolfi-base",
		})

		// Check Pipeline
		assert.Equal(t, 1, len(got.Pipeline))

		// Check Pipeline - fetch
		assert.Equal(t, got.Pipeline[0].Uses, "fetch")

		// Check Subpackages
		assert.Equal(t, "py-versions", got.Subpackages[0].Range)
		assert.Equal(t, "py3-${{vars.pypi-package}}", got.Subpackages[0].Dependencies.Provides[0])
		assert.Equal(t, "py/pip-build-install", got.Subpackages[0].Pipeline[0].Uses)
		var expectedRuntimeDeps []string = []string{
			"py3.10-jmespath",
			"py3.10-python-dateutil",
			"py3.10-urllib3",
			"python-3.10",
		}
		// Subpackages aren't added to this array in the same order every time causing spurious
		// test failues. To fix this Just check what is seen and replace the deps with the version string.
		var replacementPyVersion = got.Subpackages[0].Dependencies.Runtime[0][2:6]
		for idx, dep := range expectedRuntimeDeps {
			expectedRuntimeDeps[idx] = strings.Replace(dep, "3.10", replacementPyVersion, 1)
		}

		assert.Equal(t, expectedRuntimeDeps, got.Subpackages[0].Dependencies.Runtime)
		assert.Equal(t, "${{range.value}}", got.Subpackages[0].Dependencies.ProviderPriority)
		releases, ok := pythonctx.Package.Releases[pythonctx.PackageVersion]

		assert.Equal(t, "python/import", got.Subpackages[0].Test.Pipeline[0].Uses)
		assert.Equal(t, "${{vars.module_name}}", got.Subpackages[0].Test.Pipeline[0].With["import"])

		// If the key exists
		assert.True(t, ok)

		var release Release
		for _, r := range releases {
			if r.PackageType == "sdist" {
				release = r
			}
		}
		assert.NotEmpty(t, release)
		assert.Equal(t, "https://files.pythonhosted.org/packages/8f/34/d4bcefeabfb8e4b46157e84ea55c3ecc7399d5f9a3454728e1d0d5f9cb83/botocore-"+pythonctx.PackageVersion+".tar.gz", release.URL)

		tempURI := fmt.Sprintf("https://files.pythonhosted.org/packages/source/%c/%s/%s-%s.tar.gz", pythonctx.PackageName[0], pythonctx.PackageName, pythonctx.PackageName, pythonctx.PackageVersion)
		assert.Equal(t, got.Pipeline[0].With, map[string]string{
			"expected-sha256": "2bee6ed037590ef1e4884d944486232871513915f12a8590c63e3bb6046479bf",
			"uri":             strings.ReplaceAll(tempURI, pythonctx.PackageVersion, "${{package.version}}"),
		})

	}
}

func TestGenerateManifestPreserveURI(t *testing.T) {
	ctx := slogtest.Context(t)

	for i := range versions {
		pythonctxs, err := SetupContextPreserveURI(versions[i])
		assert.NoError(t, err)

		// typing-extensions ctx
		pythonctx := pythonctxs[0]
		// Add additional repositories and keyrings
		pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
		pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
		got, err := pythonctx.generateManifest(ctx, pythonctx.Package, pythonctx.PackageVersion, nil, nil)
		assert.NoError(t, err)

		// Check Package
		assert.Equal(t, got.Package.Name, "py"+versions[i]+"-typing-extensions")
		assert.Equal(t, got.Package.Version, "4.12.2")
		assert.EqualValues(t, got.Package.Epoch, 0)
		assert.Equal(t, got.Package.Description,
			"Backported and Experimental Type Hints for Python 3.8+",
		)
		assert.Equal(t, []string(nil), got.Package.Dependencies.Runtime)
		assert.Equal(t, "0", got.Package.Dependencies.ProviderPriority)

		// Check Package.Copyright
		assert.Equal(t, len(got.Package.Copyright), 1)
		assert.Equal(t, got.Package.Copyright[0].License, "")

		// Check Environment
		assert.Equal(t, got.Environment.Contents.Packages, []string{
			"build-base",
			"busybox",
			"ca-certificates-bundle",
			"py3-supported-build-base-dev",
			"wolfi-base",
		})

		// Check Pipeline
		assert.Equal(t, 1, len(got.Pipeline))

		// Check Pipeline - fetch
		assert.Equal(t, got.Pipeline[0].Uses, "fetch")

		releases, ok := pythonctx.Package.Releases[pythonctx.PackageVersion]

		// If the key exists
		assert.True(t, ok)

		var release Release
		for _, r := range releases {
			if r.PackageType == "sdist" {
				release = r
			}
		}
		assert.NotEmpty(t, release)
		assert.Equal(t, "https://files.pythonhosted.org/packages/df/db/f35a00659bc03fec321ba8bce9420de607a1d37f8342eee1863174c69557/typing_extensions-"+pythonctx.PackageVersion+".tar.gz", release.URL)

		assert.Equal(t, got.Pipeline[0].With, map[string]string{
			"expected-sha256": "1a7ead55c7e559dd4dee8856e3a88b41225abfe1ce8df57b7c13915fe121ffb8",
			"uri":             "https://files.pythonhosted.org/packages/df/db/f35a00659bc03fec321ba8bce9420de607a1d37f8342eee1863174c69557/typing_extensions-${{package.version}}.tar.gz",
		})

		// Check Tests
		assert.Equal(t, "python/import", got.Test.Pipeline[0].Uses)
		assert.Equal(t, "${{vars.module_name}}", got.Test.Pipeline[0].With["import"])
	}
}
