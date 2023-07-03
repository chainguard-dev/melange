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
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"

	"github.com/stretchr/testify/assert"
)

const (
	testDataDir       = "testdata/"
	botocoreMetaDir   = testDataDir + "/meta/botocore"
	jsonschemaMetaDir = testDataDir + "/meta/jsonschema"
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
	packages, err := os.ReadDir(filepath.Join(botocoreMetaDir))
	assert.NoError(t, err)
	assert.NotEmpty(t, packages)

	// Iterate through all pack metadata files and ensure the server response is
	// the same as the file.
	for _, pack := range packages {
		pythonctx, err := New(pack.Name())
		pythonctx.PackageIndex = NewPackageIndex("https://pypi.org")
		assert.NoError(t, err)

		// Read the pack meta into
		data, err := os.ReadFile(filepath.Join(botocoreMetaDir, pack.Name()))
		assert.NoError(t, err)

		var expected Package
		err = json.Unmarshal(data, &expected)
		assert.NoError(t, err)
		p := strings.Split(pack.Name(), ".")

		// Ensure expected == got
		got, err := pythonctx.PackageIndex.Get(p[0], pythonctx.PackageVersion)
		fmt.Printf("Comparing GOT %s to Expected %s\n", got.Info.Name, expected.Info.Name)
		assert.NoError(t, err)
		assert.Equal(t, expected.Info.Name, got.Info.Name)

	}
}

func TestFindDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := filepath.Join(jsonschemaMetaDir, botocoreMetaDir, req.URL.String())
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
			p, err := pythonctx.PackageIndex.Get(pythonctx.PackageName, pythonctx.PackageVersion)
			assert.NoError(t, err)
			pythonctx.ToCheck = append(pythonctx.ToCheck, p.Info.Name)

			// Build list of dependencies
			err = pythonctx.findDep()
			assert.NoError(t, err)

			//get specific python packages for package
			pythonPackages, err := GetJsonsPackagesForPackage(pythonctx.PackageName)
			assert.NoError(t, err)
			assert.NotEmpty(t, pythonPackages)

			log.Printf("[%s] Generating %v files", pythonctx.PackageName, len(pythonctx.ToGenerate))
			for _, pack := range pythonPackages {
				packName := strings.TrimSuffix(pack.Name(), ".json")
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

	for i := range versions {
		pythonctxs, err := SetupContext(versions[i])
		assert.NoError(t, err)

		//botocore ctx
		pythonctx := pythonctxs[0]
		got, err := pythonctx.generateManifest(pythonctx.Package, pythonctx.PackageVersion)
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
		assert.Equal(t, got.Environment.Contents.Repositories, []string{"https://packages.wolfi.dev/os"})
		assert.Equal(t, got.Environment.Contents.Keyring, []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"})
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
		assert.Equal(t, got.Pipeline[1].Runs, pythonBuildPipeline)
		assert.Equal(t, got.Pipeline[2].Runs, pythonInstallPipeline)
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

		expected := build.Package{
			Name:        "py" + versions[i] + "-botocore",
			Version:     "1.29.78",
			Epoch:       0,
			Description: "Low-level, data-driven core of boto 3.",
			Copyright: []build.Copyright{
				{
					License: "Apache License 2.0",
				},
			},
			Dependencies: build.Dependencies{
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

	botocorepythonctx.PackageIndex = NewPackageIndex("https://pypi.org")
	botocorepythonctx.PackageName = "botocore"
	botocorepythonctx.PackageVersion = "1.29.78"
	botocorepythonctx.PythonVersion = version

	// Read the gem meta into
	data, err := os.ReadFile(filepath.Join(botocoreMetaDir, "botocore.json"))
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

	jsonschemapythonctx.PackageIndex = NewPackageIndex("https://pypi.org")
	jsonschemapythonctx.PackageName = "jsonschema"
	jsonschemapythonctx.PackageVersion = "4.17.3"
	jsonschemapythonctx.PythonVersion = version

	// Read the gem meta into
	data, err = os.ReadFile(filepath.Join(jsonschemaMetaDir, "jsonschema.json"))
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

func GetJsonsPackagesForPackage(packageName string) ([]fs.DirEntry, error) {
	if packageName == "botocore" {
		return os.ReadDir(filepath.Join(botocoreMetaDir))
	} else if packageName == "jsonschema" {
		return os.ReadDir(filepath.Join(jsonschemaMetaDir))
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

	assert.Equal(t, got310, expected310)

	pythonctxs, err = SetupContext("3.11")

	//botocore ctx
	pythonctx = pythonctxs[0]
	assert.NoError(t, err)
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

	assert.Equal(t, got311, expected311)
}
