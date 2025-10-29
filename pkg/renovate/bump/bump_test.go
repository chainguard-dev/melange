package bump

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/renovate"
)

func TestBump_versions(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name            string
		newVersion      string
		expectedVersion string
	}{
		{name: "float_issue.yaml", newVersion: "7.0.1", expectedVersion: `version: "7.0.1"`},
		{name: "quoted.yaml", newVersion: "7.0.1", expectedVersion: `version: "7.0.1"`},
		{name: "major_minor_patch.yaml", newVersion: "7.0.1", expectedVersion: `version: "7.0.1"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			server, err := setupTestServer(t)
			assert.NoError(t, err)

			data, err := os.ReadFile(filepath.Join("testdata", tt.name))
			assert.NoError(t, err)

			// replace the melange pipeline fetch URL with our test server
			melangConfig := strings.Replace(string(data), "REPLACE_ME", server.URL, 1)

			// write the modified melange config to our working temp folder
			err = os.WriteFile(filepath.Join(dir, tt.name), []byte(melangConfig), 0o755)
			assert.NoError(t, err)

			rctx, err := renovate.New(renovate.WithConfig(filepath.Join(dir, tt.name)))
			assert.NoError(t, err)

			bumpRenovator := New(ctx,
				WithTargetVersion(tt.newVersion),
			)

			err = rctx.Renovate(slogtest.Context(t), bumpRenovator)
			assert.NoError(t, err)

			resultData, err := os.ReadFile(filepath.Join(dir, tt.name))
			assert.NoError(t, err)
			assert.Contains(t, string(resultData), tt.expectedVersion)
			assert.Contains(t, string(resultData), "expected-sha256: cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a")
		})
	}
}

func TestBump_withExpectedCommit(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name           string
		newVersion     string
		expectedCommit string
		expectedEpoch  uint64
	}{
		{name: "expected_commit.yaml", newVersion: "7.0.1", expectedCommit: "dbd7bc96fd6cd383b8e895dc4a928d808541bb17", expectedEpoch: 0},
		// sometimes upstream projects delete tags and re-use them with a different commit, so we need to bump the epoch
		{name: "expected_commit.yaml", newVersion: "6.8", expectedCommit: "dbd7bc96fd6cd383b8e895dc4a928d808541bb17", expectedEpoch: 3},
		// if there are no version or commit changes we still expect the epoch to be bumped
		{name: "expected_commit.yaml", newVersion: "6.8", expectedCommit: "foo", expectedEpoch: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			data, err := os.ReadFile(filepath.Join("testdata", tt.name))
			assert.NoError(t, err)

			// write the modified melange config to our working temp folder
			err = os.WriteFile(filepath.Join(dir, tt.name), data, 0o755)
			assert.NoError(t, err)

			rctx, err := renovate.New(renovate.WithConfig(filepath.Join(dir, tt.name)))
			assert.NoError(t, err)

			bumpRenovator := New(ctx,
				WithTargetVersion(tt.newVersion),
				WithExpectedCommit(tt.expectedCommit),
			)

			err = rctx.Renovate(slogtest.Context(t), bumpRenovator)
			assert.NoError(t, err)

			rs, err := config.ParseConfiguration(ctx, filepath.Join(dir, tt.name))
			require.NoError(t, err)
			assert.Equal(t, rs.Package.Version, tt.newVersion)
			assert.Equal(t, rs.Package.Epoch, tt.expectedEpoch)
			assert.Equal(t, rs.Pipeline[0].With["expected-commit"], tt.expectedCommit)
		})
	}
}

func TestBump_withExpectedCommitAndMangledVarsGitTag(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name           string
		newVersion     string
		expectedCommit string
		expectedEpoch  uint64
	}{
		{name: "minio.yaml", newVersion: "0.20240629.012047", expectedCommit: "91faaa13877df0e2989b1eb3821f0e82fcbbfe80", expectedEpoch: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			data, err := os.ReadFile(filepath.Join("testdata", tt.name))
			assert.NoError(t, err)

			// write the modified melange config to our working temp folder
			err = os.WriteFile(filepath.Join(dir, tt.name), data, 0o755)
			assert.NoError(t, err)

			rctx, err := renovate.New(renovate.WithConfig(filepath.Join(dir, tt.name)))
			assert.NoError(t, err)

			bumpRenovator := New(ctx,
				WithTargetVersion(tt.newVersion),
				WithExpectedCommit(tt.expectedCommit),
			)

			err = rctx.Renovate(slogtest.Context(t), bumpRenovator)
			assert.NoError(t, err)

			rs, err := config.ParseConfiguration(ctx, filepath.Join(dir, tt.name))
			require.NoError(t, err)
			assert.Equal(t, rs.Package.Version, tt.newVersion)
			assert.Equal(t, rs.Package.Epoch, tt.expectedEpoch)
			assert.Equal(t, rs.Pipeline[0].With["expected-commit"], tt.expectedCommit)
		})
	}
}

func TestBump_withMultipleCheckouts(t *testing.T) {
	dir := t.TempDir()
	filename := "multiple_checkouts.yaml"

	data, err := os.ReadFile(filepath.Join("testdata", filename))
	assert.NoError(t, err)

	// write the modified melange config to our working temp folder
	err = os.WriteFile(filepath.Join(dir, filename), data, 0o755)
	assert.NoError(t, err)

	rctx, err := renovate.New(renovate.WithConfig(filepath.Join(dir, filename)))
	assert.NoError(t, err)

	ctx := slogtest.Context(t)

	bumpRenovator := New(ctx,
		WithTargetVersion("6.8"),
		WithExpectedCommit("1234abcd"),
	)

	err = rctx.Renovate(slogtest.Context(t), bumpRenovator)
	assert.NoError(t, err)

	rs, err := config.ParseConfiguration(ctx, filepath.Join(dir, filename))
	require.NoError(t, err)
	assert.Equal(t, rs.Pipeline[0].With["expected-commit"], "1234abcd")
	assert.Equal(t, rs.Pipeline[1].With["expected-commit"], "bar")
}

func setupTestServer(t *testing.T) (*httptest.Server, error) {
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
	return server, err
}
