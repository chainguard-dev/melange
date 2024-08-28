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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
)

const (
	testDataDir    = "testdata/"
	botocoreMeta   = testDataDir + "/meta/pypi/botocore/"
	jsonschemaMeta = testDataDir + "/meta/pypi/jsonschema/"
	typingextMeta  = testDataDir + "/meta/pypi/typing-extensions/"
	pypiMetaDir    = testDataDir + "/meta"
)

var versions = [2]string{"3.11", "3.10"}

// var testdata = []string{"botocore", "jmespath", "python-dateutil", "urllib3", "six"}

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
	pythonctx.PackageIndex.Client.Ratelimiter = nil // don't rate limit our unit tests
	assert.NoError(t, err)

	var expected Package
	err = json.Unmarshal(p, &expected)
	assert.NoError(t, err)

	// Ensure expected == got
	got, err := pythonctx.PackageIndex.Get(slogtest.Context(t), "botocore", pythonctx.PackageVersion)
	assert.NoError(t, err)
	assert.Equal(t, expected.Info.Name, got.Info.Name)
}

func TestFindDependencies(t *testing.T) {
	ctx := slogtest.Context(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		log := clog.FromContext(ctx)
		latestVersion, err := removeVersionsFromURL(req.URL.String())
		assert.NoError(t, err)
		path := filepath.Join(pypiMetaDir, latestVersion)
		log.Infof("convert:test:server: %s", path)

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
			pythonctx.PackageIndex.Client.Ratelimiter = nil // don't rate limit our unit tests
			p, err := pythonctx.PackageIndex.Get(slogtest.Context(t), pythonctx.PackageName, pythonctx.PackageVersion)
			assert.NoError(t, err)
			pythonctx.ToCheck = append(pythonctx.ToCheck, p.Info.Name)

			// Build list of dependencies
			err = pythonctx.findDep(slogtest.Context(t))
			assert.NoError(t, err)

			// get specific python packages for package
			pythonPackages, err := GetJsonsPackagesForPackage(pythonctx.PackageName)
			assert.NoError(t, err)
			assert.NotEmpty(t, pythonPackages)

			clog.FromContext(ctx).Infof("[%s] Generating %v files", pythonctx.PackageName, len(pythonctx.ToGenerate))
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

// TestGeneratePackage tests when a python package has multiple licenses
func TestGeneratePackage(t *testing.T) {
	for i := range versions {
		pythonctxs, err := SetupContext(versions[i])
		assert.NoError(t, err)

		// botocore ctx
		pythonctx := pythonctxs[0]
		got := pythonctx.generatePackage(slogtest.Context(t), pythonctx.Package, pythonctx.PackageVersion)

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
				Runtime:          []string{"py" + versions[i] + "-jmespath", "py" + versions[i] + "-python-dateutil", "py" + versions[i] + "-urllib3", "python-" + versions[i]},
				ProviderPriority: "0",
			},
		}

		assert.Equal(t, expected, got)
	}
}

func SetupContext(version string) ([]*PythonContext, error) {
	botocorepythonctx, err := New("botocore")
	if err != nil {
		return nil, err
	}

	botocorepythonctx.PackageIndex = NewPackageIndex("https://pypi.org/")
	botocorepythonctx.PackageIndex.Client.Ratelimiter = nil // don't rate limit our unit tests
	botocorepythonctx.PackageName = "botocore"
	botocorepythonctx.PackageVersion = "1.29.78"
	botocorepythonctx.PythonVersion = version

	// Read the pypi meta into
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
	botocorepythonctx.Package.Dependencies = []string{"py" + version + "-jmespath", "py" + version + "-python-dateutil", "py" + version + "-urllib3", "python-" + version}

	jsonschemapythonctx, err := New("jsonschema")
	if err != nil {
		return nil, err
	}

	jsonschemapythonctx.PackageIndex = NewPackageIndex("https://pypi.org/")
	jsonschemapythonctx.PackageIndex.Client.Ratelimiter = nil // don't rate limit our unit tests
	jsonschemapythonctx.PackageName = "jsonschema"
	jsonschemapythonctx.PackageVersion = "4.17.3"
	jsonschemapythonctx.PythonVersion = version

	// Read the pypi meta into
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

func SetupContextPreserveURI(version string) ([]*PythonContext, error) {
	typingextctx, err := New("typing-extensions")
	if err != nil {
		return nil, err
	}

	typingextctx.PackageIndex = NewPackageIndex("https://pypi.org/")
	typingextctx.PackageIndex.Client.Ratelimiter = nil // don't rate limit our unit tests
	typingextctx.PackageName = "typing-extensions"
	typingextctx.PackageVersion = "4.12.2"
	typingextctx.PythonVersion = version
	typingextctx.PreserveBaseURI = true

	// Read the pypi package meta into
	data, err := os.ReadFile(filepath.Join(typingextMeta, "json"))
	if err != nil {
		return nil, err
	}

	var typingextPackageMeta Package
	err = json.Unmarshal(data, &typingextPackageMeta)
	if err != nil {
		return nil, err
	}

	typingextctx.Package = typingextPackageMeta
	typingextctx.Package.Dependencies = []string{}

	pythonctxs := []*PythonContext{
		&typingextctx,
	}
	return pythonctxs, nil
}

func GetJsonsPackagesForPackage(packageName string) ([]string, error) {
	if packageName == "botocore" {
		return []string{"botocore", "jmespath", "python-dateutil", "urllib3", "six"}, nil
	} else if packageName == "jsonschema" {
		return []string{"jsonschema", "attrs", "importlib-metadata", "importlib-resources", "pkgutil-resolve-name", "pyrsistent", "typing-extensions", "zipp"}, nil
	} else if packageName == "typing-extensions" {
		return []string{"typing-extensions"}, nil
	}
	return nil, fmt.Errorf("Unknown package %s", packageName)
}

// TestGenerateEnvironment tests when there are additional keyring and
// repository entries
func TestGenerateEnvironment(t *testing.T) {
	pythonctxs, err := SetupContext("3.10")
	assert.NoError(t, err)

	// botocore ctx
	pythonctx := pythonctxs[0]

	pythonctx.PythonVersion = "3.10"
	// Add additionalReposities and additionalKeyrings
	pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
	pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
	got310 := pythonctx.generateEnvironment(slogtest.Context(t), pythonctx.Package)

	expected310 := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: []string{
				"build-base",
				"busybox",
				"ca-certificates-bundle",
				"py3-supported-pip",
				"wolfi-base",
			},
		},
	}

	assert.Equal(t, expected310, got310)

	pythonctxs, err = SetupContext("3.11")

	// botocore ctx
	pythonctx = pythonctxs[0]
	assert.NoError(t, err)
	pythonctx.AdditionalRepositories = []string{"https://packages.wolfi.dev/os"}
	pythonctx.AdditionalKeyrings = []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}

	got311 := pythonctx.generateEnvironment(slogtest.Context(t), pythonctx.Package)

	expected311 := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: []string{
				"build-base",
				"busybox",
				"ca-certificates-bundle",
				"py3-supported-pip",
				"wolfi-base",
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
