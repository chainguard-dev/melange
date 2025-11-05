package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/renovate"
)

func TestCache(t *testing.T) {
	dir := t.TempDir()
	cacheDir := t.TempDir()

	server, err := setupTestServer(t)
	assert.NoError(t, err)

	name := "cheese.yaml"
	data, err := os.ReadFile(filepath.Join("testdata", name))
	assert.NoError(t, err)

	// replace the melange pipeline fetch URL with our test server
	melangConfig := strings.Replace(string(data), "REPLACE_ME", server.URL, 1)

	// write the modified melange config to our working temp folder
	err = os.WriteFile(filepath.Join(dir, name), []byte(melangConfig), 0o755)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(filepath.Join(dir, name)))
	assert.NoError(t, err)

	rc := renovate.RenovationContext{Context: rctx}

	cacheRenovator := New(WithCacheDir(cacheDir))

	assert.NoError(t, rc.LoadConfig(t.Context()))

	assert.NoError(t, cacheRenovator(t.Context(), &rc))

	cached, err := os.ReadFile(filepath.Join(cacheDir, "sha256:cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a"))
	assert.NoError(t, err)

	h := sha256.New()
	h.Write(cached)
	assert.Equal(t, "sha256:"+hex.EncodeToString(h.Sum(nil)), "sha256:cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a")
}

func setupTestServer(t *testing.T) (*httptest.Server, error) {
	packageData, err := os.ReadFile(filepath.Join("../bump/testdata", "cheese-7.0.1.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Logf("%s %s", req.Method, req.URL.String())
		// Test request parameters
		assert.Equal(t, "/wine/cheese/cheese-7.0.1.tar.gz", req.URL.String())

		// Send response to be tested
		_, err = rw.Write(packageData)
		assert.NoError(t, err)
	}))
	return server, err
}
