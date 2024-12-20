package gem

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkotypes "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/config"
	rlhttp "chainguard.dev/melange/pkg/http"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
)

const (
	testDataDir = "testdata"
	gemMetaDir  = testDataDir + "/gem_meta"
	archiveDir  = testDataDir + "/archive"
)

func testGemContext(base string) *GemContext {
	return &GemContext{
		Client: &rlhttp.RLHTTPClient{
			Client: http.DefaultClient,
		},
		ToGenerate:    make(map[string]GemMeta),
		BaseURIFormat: base,
	}
}

func TestGetGemMeta(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		log := clog.FromContext(ctx)

		path := filepath.Join(gemMetaDir, req.URL.String())
		log.Infof("convert:test:server: %s", path)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		_, err = w.Write(data)
		assert.NoError(t, err)
	}))
	defer server.Close()

	// Get list of all gem metadata files in testdata dir
	gems, err := os.ReadDir(filepath.Join(gemMetaDir))
	assert.NoError(t, err)
	assert.NotEmpty(t, gems)

	// Iterate through all gem metadata files and ensure the server response is
	// the same as the file.
	for _, gem := range gems {
		gemctx := testGemContext(server.URL + "/%s.json")

		// Read the gem meta into
		data, err := os.ReadFile(filepath.Join(gemMetaDir, gem.Name()))
		assert.NoError(t, err)

		var expected GemMeta
		err = json.Unmarshal(data, &expected)
		assert.NoError(t, err)

		expected.RepoURI = expected.SourceCodeURI
		if expected.SourceCodeURI == "" {
			expected.RepoURI = expected.HomepageURI
		}

		gemURL := fmt.Sprintf("%s/%s/", server.URL, gem.Name())
		assert.NoError(t, err)

		// Ensure expected == got
		got, err := gemctx.getGemMeta(slogtest.Context(t), gemURL)
		assert.NoError(t, err)
		assert.Equal(t, expected, got)
	}
}

func TestFindDependencies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log := clog.FromContext(req.Context())
		path := filepath.Join(gemMetaDir, req.URL.String())
		log.Infof("convert:test:server: %s", path)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		_, err = w.Write(data)
		assert.NoError(t, err)
	}))
	defer server.Close()

	gems, err := os.ReadDir(filepath.Join(gemMetaDir))
	assert.NoError(t, err)
	assert.NotEmpty(t, gems)

	gemctx := testGemContext(server.URL + "/%s.json")
	gemctx.ToCheck = []string{"async"}

	// Build list of dependencies
	err = gemctx.findDependencies(slogtest.Context(t))
	assert.NoError(t, err)

	for _, gem := range gems {
		gemName := strings.TrimSuffix(gem.Name(), ".json")
		_, ok := gemctx.ToGenerate[gemName]
		assert.True(t, ok)

		// Remove dependency from the list
		delete(gemctx.ToGenerate, gemName)
	}
	// The dependency list should be empty
	assert.Empty(t, gemctx.ToGenerate)
}

func TestGenerateManifest(t *testing.T) {
	// Serve up testdata/archive
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		log := clog.FromContext(req.Context())
		// req.URL.String() will include /archive/refs/tags/ which we want to remove
		path := filepath.Join(archiveDir, strings.ReplaceAll(req.URL.String(), "/archive/refs/tags/", "/"))
		log.Infof("convert:test:server: %s", path)

		data, err := os.ReadFile(path)
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		_, err = w.Write(data)
		assert.NoError(t, err)
	}))
	defer server.Close()

	gemctx := testGemContext(server.URL + "/%s.json")

	gemctx.RubyVersion = DefaultRubyVersion

	// Read the gem meta into
	data, err := os.ReadFile(filepath.Join(gemMetaDir, "async.json"))
	assert.NoError(t, err)

	var g GemMeta
	err = json.Unmarshal(data, &g)
	assert.NoError(t, err)

	g.RepoURI = server.URL

	got, err := gemctx.generateManifest(slogtest.Context(t), g)
	assert.NoError(t, err)

	// Check Package
	assert.Equal(t, fmt.Sprintf("ruby%s-async", DefaultRubyVersion), got.Package.Name)
	assert.Equal(t, "2.3.1", got.Package.Version)
	assert.EqualValues(t, 0, got.Package.Epoch)
	assert.Equal(t, "A concurrency framework for Ruby.", got.Package.Description)

	// Check Package.Copyright
	assert.Equal(t, 1, len(got.Package.Copyright))
	assert.Equal(t, "MIT", got.Package.Copyright[0].License)

	// Check Environment
	assert.Equal(t, []string{
		"build-base",
		"busybox",
		"ca-certificates-bundle",
		"git",
		"ruby-${{vars.rubyMM}}",
		"ruby-${{vars.rubyMM}}-dev",
	}, got.Environment.Contents.Packages)

	// Check Pipeline
	assert.Equal(t, 4, len(got.Pipeline))

	// Check Pipeline - fetch
	assert.Equal(t, "fetch", got.Pipeline[0].Uses)
	// NOTE: The sha256 here is the sha256 of the v2.3.1.tar.gz in the testdata/archive
	//       directory, which is just a tarball of the async.json, not the
	//       actual artifact. It's simply used for testing.
	assert.Equal(t, map[string]string{
		"expected-sha256": "2481a44fc272b64a4a1775edf57c52b5367c8a07afd7996901d3c57c77542e6c",
		"uri":             fmt.Sprintf("%s/archive/refs/tags/v${{package.version}}.tar.gz", server.URL),
	}, got.Pipeline[0].With)

	// Check Pipeline - ruby/build
	assert.Equal(t, "ruby/build", got.Pipeline[1].Uses)
	assert.Equal(t, map[string]string{
		"gem": "${{vars.gem}}",
	}, got.Pipeline[1].With)

	// Check Pipeline - ruby/install
	assert.Equal(t, "ruby/install", got.Pipeline[2].Uses)
	assert.Equal(t, map[string]string{
		"gem":     "${{vars.gem}}",
		"version": "${{package.version}}",
	}, got.Pipeline[2].With)

	// Check Pipeline - ruby/clean
	assert.Equal(t, "ruby/clean", got.Pipeline[3].Uses)
}

// TestGeneratePackage tests when a gem has multiple licenses
func TestGeneratePackage(t *testing.T) {
	g := GemMeta{
		Name:     "app",
		Info:     "info",
		Version:  "v2.3.1",
		Licenses: []string{"MIT", "Ruby"},
	}

	expected := config.Package{
		Epoch:       0,
		Name:        fmt.Sprintf("ruby-%s", g.Name),
		Description: g.Info,
		Version:     g.Version,
		Copyright: []config.Copyright{
			{
				License: "MIT",
			}, {
				License: "Ruby",
			},
		},
		Dependencies: config.Dependencies{
			Runtime: []string{},
		},
	}

	gemctx := testGemContext("unused")

	got := gemctx.generatePackage(g)
	assert.Equal(t, expected, got)
}

func TestGenerateEnvironment(t *testing.T) {
	expected := apkotypes.ImageConfiguration{
		Contents: apkotypes.ImageContents{
			Packages: []string{
				"build-base",
				"busybox",
				"ca-certificates-bundle",
				"git",
				"ruby-${{vars.rubyMM}}",
				"ruby-${{vars.rubyMM}}-dev",
			},
		},
	}

	gemctx := testGemContext("unused")

	gemctx.RubyVersion = DefaultRubyVersion

	got := gemctx.generateEnvironment()
	assert.Equal(t, expected, got)
}
