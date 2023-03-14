package wolfios

import (
	"net/http"
	"net/http/httptest"

	"github.com/stretchr/testify/assert"

	"os"
	"path/filepath"
	"testing"
)

func Test_getWolfiPackages(t *testing.T) {

	data, err := os.ReadFile(filepath.Join("testdata", "APKINDEX.tar.gz"))
	assert.NoError(t, err)

	// create a test server for melange bump to fetch the tarball and generate SHA
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/APKINDEX.tar.gz")

		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)

	}))

	c := New(server.Client(), server.URL+"/APKINDEX.tar.gz")
	wolfiPackages, err := c.GetWolfiPackages()
	assert.NoError(t, err)
	assert.True(t, wolfiPackages["pkgconf-doc"])
	assert.True(t, wolfiPackages["wolfi-baselayout"])
	assert.True(t, wolfiPackages["bash-doc"])

}
