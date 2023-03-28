package bump

import (
	"chainguard.dev/melange/pkg/build"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBump_versions(t *testing.T) {

	dir := t.TempDir()

	tests := []struct {
		name            string
		newVersion      string
		expectedVersion string
	}{
		{name: "float_issue.yaml", newVersion: "7.0.1", expectedVersion: "version: 7.0.1"},
		{name: "quoted.yaml", newVersion: "7.0.1", expectedVersion: "version: 7.0.1"},
		{name: "major_minor_patch.yaml", newVersion: "7.0.1", expectedVersion: "version: 7.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err, server := setupTestServer(t)
			assert.NoError(t, err)

			data, err := os.ReadFile(filepath.Join("testdata", tt.name))
			assert.NoError(t, err)

			// replace the melange pipeline fetch URL with our test server
			melangConfig := strings.Replace(string(data), "REPLACE_ME", server.URL, 1)

			// write the modified melange config to our working temp folder
			err = os.WriteFile(filepath.Join(dir, tt.name), []byte(melangConfig), 0755)
			assert.NoError(t, err)

			ctx, err := build.New(build.WithConfig(filepath.Join(dir, tt.name)))
			assert.NoError(t, err)

			bumpRenovator := New(
				WithTargetVersion(tt.newVersion),
			)

			err = ctx.Renovate(bumpRenovator)
			assert.NoError(t, err)

			resultData, err := os.ReadFile(filepath.Join(dir, tt.name))
			assert.NoError(t, err)
			assert.Contains(t, string(resultData), tt.expectedVersion)
			assert.Contains(t, string(resultData), "expected-sha256: cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a")

		})
	}

}

func setupTestServer(t *testing.T) (error, *httptest.Server) {
	packageData, err := os.ReadFile(filepath.Join("testdata", "cheese-7.0.1.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/wine/cheese/cheese-7.0.1.tar.gz")

		// Send response to be tested
		_, err = rw.Write(packageData)
		assert.NoError(t, err)

	}))
	return err, server
}
