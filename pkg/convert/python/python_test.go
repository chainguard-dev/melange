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
package python

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"

	"github.com/stretchr/testify/assert"
)

const (
	testDataDir    = "testdata/"
	botocoreMeta   = testDataDir + "/meta/pypi/botocore/"
	jsonschemaMeta = testDataDir + "/meta/pypi/jsonschema/"
	pypiMetaDir    = testDataDir + "/meta"
)

var versions = [2]string{"3.11", "3.10"}

//var testdata = []string{"botocore", "jmespath", "python-dateutil", "urllib3", "six"}

/*func TestGetTestData(t *testing.T) {
	for _, pack := range testdata {
		pythonctx, err := New(pack)
		pythonctx.PackageIndex = NewPackageIndex("https://pypi.org")
		assert.NoError(t, err)

		// Ensure expected == got
		data, err := pythonctx.PackageIndex.GetLatest(pack)
		assert.NoError(t, err)

		file, _ := json.MarshalIndent(data, "", " ")
		filename := fmt.Sprintf("testdata/meta/%s.json", pack)
		err = os.WriteFile(filename, file, 0666)
		assert.NoError(t, err)
	}
}*/

func TestGetPythonMeta(t *testing.T) {

	// Get list of all python metadata files in testdata dir
	p, err := os.ReadFile(filepath.Join(botocoreMeta, "json"))
	assert.NoError(t, err)
	assert.NotEmpty(t, p)

	pythonctx, err := New("botocore")
	pythonctx.PackageIndex = NewPackageIndex("https://pypi.org")
	assert.NoError(t, err)

	var expected Package
	err = json.Unmarshal(p, &expected)
	assert.NoError(t, err)

	// Ensure expected == got
	got, err := pythonctx.PackageIndex.Get(context.Background(), "botocore", pythonctx.PackageVersion)
	fmt.Printf("Comparing GOT %s to Expected %s\n", got.Info.Name, expected.Info.Name)
	assert.NoError(t, err)
	assert.Equal(t, expected.Info.Name, got.Info.Name)
}

func TestFindDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		latestVersion, err := removeVersionsFromURL(req.URL.String())
		assert.NoError(t, err)
		path := filepath.Join(pypiMetaDir, latestVersion)
		log.Printf("convert:test:server: %s", path)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		_, err = w.Write(data)
		assert.NoError(t, err)
	}))

	defer server.Close()

	for i := range versions {
		pythonctxs, err := SetupContext(versions[i])
		assert.NoError(t, err)

		for _, pythonctx := range pythonctxs {
			pythonctx.PackageIndex.url = server.URL
			p, err := pythonctx.PackageIndex.Get(context.Background(), pythonctx.PackageName, pythonctx.PackageVersion)
			assert.NoError(t, err)
			pythonctx.ToCheck = append(pythonctx.ToCheck, p.Info.Name)

			// Build list of dependencies
			err = pythonctx.findDep(context.Background())
			assert.NoError(t, err)

			//get specific python packages for package
			pythonPackages, err := GetJsonsPackagesForPackage(pythonctx.PackageName)
			assert.NoError(t, err)
			assert.NotEmpty(t, pythonPackages)

			log.Printf("[%s] Generating %v files", pythonctx.PackageName, len(pythonctx.ToGenerate))
			for _, packName := range pythonPackages {
				_, ok := pythonctx.ToGenerate[packName]
				assert.True(t, ok)

				// Remove dependency from the list
				delete(pythonctx.ToGenerate, packName)
			}
			// The dependency list should be empty
			assert.Empty(t, pythonctx.ToGenerate)
		}

	}
}

func TestGenerateManifest(t *testing.T) {
	ctx := context.Background()

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
		assert.Equal(t, got.Package.Dependencies.Runtime, []string{"py" + versions[i] + "-jmespath", "py" + versions[i] + "-python-dateutil", "py" + versions[i] + "-urllib3", "python-" + versions[i]})

		// Check Package.Copyright
		assert.Equal(t, len(got.Package.Copyright), 1)
		assert.Equal(t, got.Package.Copyright[0].License, "Apache License 2.0")

		// Check Environment
		assert.Equal(t, []string{"https://packages.wolfi.dev/os"}, got.Environment.Contents.Repositories)
		assert.Equal(t, []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}, got.Environment.Contents.Keyring)
		assert.Equal(t, got.Environment.Contents.Packages, []string{
			"ca-certificates-bundle",
			"wolfi-base",
			"busybox",
			"build-base",
			"python-" + pythonctx.PythonVersion,
			"py" + pythonctx.PythonVersion + "-setuptools",
		})

		// Check Pipeline
		assert.Equal(t, len(got.Pipeline), 4)

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
		assert.Equal(t, "https://files.pythonhosted.org/packages/8f/34/d4bcefeabfb8e4b46157e84ea55c3ecc7399d5f9a3454728e1d0d5f9cb83/botocore-"+pythonctx.PackageVersion+".tar.gz", release.Url)

		assert.Equal(t, got.Pipeline[0].With, map[string]string{
			"README":          fmt.Sprintf("CONFIRM WITH: curl -L %s | sha256sum", release.Url),
			"expected-sha256": "2bee6ed037590ef1e4884d944486232871513915f12a8590c63e3bb6046479bf",
			"uri":             strings.ReplaceAll(release.Url, pythonctx.PackageVersion, "${{package.version}}"),
		})

		// Check Pipeline - runs
		assert.Equal(t, got.Pipeline[1].Uses, "python/build")
		assert.Equal(t, got.Pipeline[2].Uses, "python/install")
		assert.Equal(t, got.Pipeline[3].Uses, "strip")
	}
}

// TestGeneratePackage tests when a gem has multiple licenses
func TestGeneratePackage(t *testing.T) {
	for i := range versions {
		pythonctxs, err := SetupContext(versions[i])
		assert.NoError(t, err)

		//botocore ctx
		pythonctx := pythonctxs[0]
		got := pythonctx.generatePackage(pythonctx.Package, pythonctx.PackageVersion)

		expected := config.Package{
			Name:        "py" + versions[i] + "-botocore",
			Version:     "1.29.78",
			Epoch:       0,
			Description: "Low-level, data-driven core of boto 3.",
			Copyright: []config.Copyright{
				{
					License: "Apache License 2.0",
				},
			},
			Dependencies: config.Dependencies{
				Runtime: []string{"py" + versions[i] + "-jmespath", "py" + versions[i] + "-python-dateutil", "py" + versions[i] + "-urllib3", "python-" + versions[i]},
			},
		}

		assert.Equal(t, got, expected)
	}
}

func SetupContext(version string) ([]*PythonContext, error) {
	botocorepythonctx, err := New("botocore")
	if err != nil {
		return nil, err
	}

	botocorepythonctx.PackageIndex = NewPackageIndex("https://pypi.org/")
	botocorepythonctx.PackageName = "botocore"
	botocorepythonctx.PackageVersion = "1.29.78"
	botocorepythonctx.PythonVersion = version

	// Read the gem meta into
	data, err := os.ReadFile(filepath.Join(botocoreMeta, "json"))
	if err != nil {
		return nil, err
	}

	var botocorePackageMeta Package
	err = json.Unmarshal(data, &botocorePackageMeta)
	if err != nil {
		return nil, err
	}

	botocorepythonctx.Package = botocorePackageMeta
	botocorepythonctx.Package.Dependencies = []string{"py" + version + "-jmespath", "py" + version + "-python-dateutil", "py" + version + "-urllib3"}

	jsonschemapythonctx, err := New("jsonschema")
	if err != nil {
		return nil, err
	}

	jsonschemapythonctx.PackageIndex = NewPackageIndex("https://pypi.org/")
	jsonschemapythonctx.PackageName = "jsonschema"
	jsonschemapythonctx.PackageVersion = "4.17.3"
	jsonschemapythonctx.PythonVersion = version

	// Read the gem meta into
	data, err = os.ReadFile(filepath.Join(jsonschemaMeta, "json"))
	if err != nil {
		return nil, err
	}

	var jsonschemaPackageMeta Package
	err = json.Unmarshal(data, &jsonschemaPackageMeta)
	if err != nil {
		return nil, err
	}

	jsonschemapythonctx.Package = botocorePackageMeta
	jsonschemapythonctx.Package.Dependencies = []string{"py" + version + "-attrs", "py" + version + "-importlib-metadata", "py" + version + "-importlib-resources", "py" + version + "-pkgutil-resolve-name", "py" + version + "-pyrsistent", "py" + version + "-typing-extensions"}

	pythonctxs := []*PythonContext{
		&botocorepythonctx,
		&jsonschemapythonctx,
	}
	return pythonctxs, nil
}

func GetJsonsPackagesForPackage(packageName string) ([]string, error) {
	if packageName == "botocore" {
		return []string{"botocore", "jmespath", "python-dateutil", "urllib3", "six"}, nil
	} else if packageName == "jsonschema" {
		return []string{"jsonschema", "attrs", "importlib-metadata", "importlib-resources", "pkgutil_resolve_name", "pyrsistent", "typing-extensions", "zipp"}, nil
	}
	return nil, fmt.Errorf("Unknown package %s", packageName)
}

// TestGenerateEnvironment tests when there are additional keyring and
// repository entries
func TestGenerateEnvironment(t *testing.T) {
	pythonctxs, err := SetupContext("3.10")
	assert.NoError(t, err)

	//botocore ctx
	pythonctx := pythonctxs[0]

	pythonctx.PythonVersion = "3.10"
	// Add additionalReposities and additionalKeyrings
	pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
	pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
	got310 := pythonctx.generateEnvironment(pythonctx.Package)

	expected310 := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
			Packages: []string{
				"ca-certificates-bundle",
				"wolfi-base",
				"busybox",
				"build-base",
				"python-" + pythonctx.PythonVersion,
				"py" + pythonctx.PythonVersion + "-setuptools",
			},
		},
	}

	assert.Equal(t, expected310, got310)

	pythonctxs, err = SetupContext("3.11")

	//botocore ctx
	pythonctx = pythonctxs[0]
	assert.NoError(t, err)
	pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
	pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}

	got311 := pythonctx.generateEnvironment(pythonctx.Package)

	expected311 := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Repositories: []string{"https://packages.wolfi.dev/os"},
			Keyring:      []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"},
			Packages: []string{
				"ca-certificates-bundle",
				"wolfi-base",
				"busybox",
				"build-base",
				"python-" + pythonctx.PythonVersion,
				"py" + pythonctx.PythonVersion + "-setuptools",
			},
		},
	}

	assert.Equal(t, expected311, got311)
}

func removeVersionsFromURL(inputURL string) (string, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return "", err
	}

	path := strings.TrimSuffix(parsedURL.Path, "/")
	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if strings.Contains(segments[i], ".") {
			segments = append(segments[:i], segments[i+1:]...)
			break
		}
	}

	parsedURL.Path = strings.Join(segments, "/")
	return parsedURL.String(), nil
}
