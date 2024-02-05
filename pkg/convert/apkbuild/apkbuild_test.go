package apkbuild

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chainguard.dev/melange/pkg/util"

	rlhttp "chainguard.dev/melange/pkg/http"
	"chainguard.dev/melange/pkg/manifest"

	"chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"gitlab.alpinelinux.org/alpine/go/apkbuild"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

func TestGetApkDependencies(t *testing.T) {
	deps, err := os.ReadDir(filepath.Join("testdata", "deps"))
	assert.NoError(t, err)
	assert.NotEmpty(t, deps)

	var filenames []string
	for _, dep := range deps {
		filenames = append(filenames, "/"+dep.Name())
	}

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// assert requests dependency is in the list of test files
		assert.True(t, util.Contains(filenames, req.URL.String()), "requests file does not match any test files")

		// send response to be tested
		data, err := os.ReadFile(filepath.Join("testdata", "deps", "/"+req.URL.String()))
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	// Close the server when test finishes
	defer server.Close()

	tctx := getTestContext(t, server)

	// the top level APKBUILD is cheese
	err = tctx.Generate(context.Background(), server.URL+"/"+"cheese", "cheese")
	assert.NoError(t, err)

	// assert all dependencies were found
	_, exists := tctx.ApkConvertors["bar"]
	assert.True(t, exists, "bar not found")
	_, exists = tctx.ApkConvertors["beer"]
	assert.True(t, exists, "beer not found")
	_, exists = tctx.ApkConvertors["cheese"]
	assert.True(t, exists, "cheese not found")
	_, exists = tctx.ApkConvertors["crisps"]
	assert.True(t, exists, "crisps not found")
	_, exists = tctx.ApkConvertors["foo"]
	assert.True(t, exists, "foo not found")
	_, exists = tctx.ApkConvertors["wine"]
	assert.True(t, exists, "wine not found")

	// assert correct order
	assert.Equal(t, []string{"bar", "foo", "crisps", "wine", "beer", "cheese"}, tctx.OrderedKeys)
}

func TestGetApkBuildFile(t *testing.T) {
	pkgName := "util-macros"

	data, err := os.ReadFile(filepath.Join("testdata", "APKBUILD_DATA"))
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Test request parameters
		assert.Equal(t, req.URL.String(), "/"+pkgName)
		// Send response to be tested
		_, err = rw.Write(data)
		assert.NoError(t, err)
	}))

	// Close the server when test finishes
	defer server.Close()

	tctx := getTestContext(t, server)

	tctx.Client.Client = server.Client()
	err = tctx.getApkBuildFile(context.Background(), server.URL+"/"+pkgName, pkgName)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(tctx.ApkConvertors), "apk converter not found")

	parsedApkbuild := tctx.ApkConvertors[pkgName].Apkbuild
	assert.Equal(t, "libx11", parsedApkbuild.Pkgname)
	assert.Equal(t, "1.8.1", parsedApkbuild.Pkgver)
	assert.Equal(t, "1", parsedApkbuild.Pkgrel)
	assert.Equal(t, "X11 client-side library", parsedApkbuild.Pkgdesc)
	assert.Equal(t, "https://xorg.freedesktop.org/", parsedApkbuild.Url)
	assert.Equal(t, apkbuild.Arches{"all"}, parsedApkbuild.Arch)
	assert.Equal(t, "custom:XFREE86", parsedApkbuild.License)
	assert.Equal(t, []apkbuild.Source{{Filename: "libX11-1.8.1.tar.xz", Location: "https://www.x.org/releases/individual/lib/libX11-1.8.1.tar.xz"}}, parsedApkbuild.Source)

	assert.Equal(t, 3, len(parsedApkbuild.Subpackages))
	assert.Equal(t, "libx11-static", parsedApkbuild.Subpackages[0].Subpkgname)
	assert.Equal(t, "libx11-dev", parsedApkbuild.Subpackages[1].Subpkgname)
	assert.Equal(t, "libx11-doc", parsedApkbuild.Subpackages[2].Subpkgname)

	assert.Equal(t, 2, len(parsedApkbuild.DependsDev))
	assert.Equal(t, "libxcb-dev", parsedApkbuild.DependsDev[0].Pkgname)
	assert.Equal(t, "xtrans", parsedApkbuild.DependsDev[1].Pkgname)

	assert.Equal(t, 5, len(parsedApkbuild.Makedepends))
	assert.Equal(t, "libxcb-dev", parsedApkbuild.Makedepends[0].Pkgname)
	assert.Equal(t, "xtrans", parsedApkbuild.Makedepends[1].Pkgname)
	assert.Equal(t, "xorgproto", parsedApkbuild.Makedepends[2].Pkgname)
	assert.Equal(t, "util-macros", parsedApkbuild.Makedepends[3].Pkgname)
	assert.Equal(t, "xmlto", parsedApkbuild.Makedepends[4].Pkgname)
}

func TestContext_getSourceSha(t *testing.T) {
	type fields struct {
		ExpectedSha    string
		Sha512         string
		TestURL        string
		PackageVersion string
	}
	var tests = []struct {
		name   string
		fields fields
	}{
		{
			name: "tar.xz",
			fields: fields{
				TestURL:        "foo-1.2.3.tar.xz",
				PackageVersion: "1.2.3",
				Sha512:         "45c3e1ad1cc945ba83cf95e439d9d83520df955e53612efd592f53c173a118a949780c619bb744631c0867474bd770dc0308e0669732ab5d4bffcf417f3e9014",
				ExpectedSha:    "6b23c4b39242db1d58ab397387b7a3a325e903cd4df332f5a089ac63cc1ca049",
			},
		},
		{
			name: "tar.gz",
			fields: fields{
				TestURL:        "bar-4.5.6.tar.gz",
				PackageVersion: "4.5.6",
				Sha512:         "3676c02e883fc26800bcd8542c4cc476a00fb5505c5019433c8316a401565317630803150d8a75d1f3111909c445b700dd123d3c0310a56849d76ed9f72da5cd",
				ExpectedSha:    "cc2c52929ace57623ff517408a577e783e10042655963b2c8f0633e109337d7a",
			},
		},
		{
			name: "tar.bz2",
			fields: fields{
				TestURL:        "cheese-7.8.9.tar.bz2",
				PackageVersion: "7.8.9",
				Sha512:         "2a83fd55473a74d2cf4110449070978fb5765cac13862ab926f1af3b88259e80dac61ec3a82319cf7fabfc90427436d73d70f201c28504f8222fb908e00bd797",
				ExpectedSha:    "8452aa9c8cefc805c8930bc53394c7de15f43edc82dd86e619d794cd7f60b410",
			},
		},
		{
			name: "bad",
			fields: fields{
				TestURL:        "cheese-7.8.9.tar.bz2",
				PackageVersion: "7.8.9",
				Sha512:         "nonmatchingsha512",
				ExpectedSha:    "SHA512 DOES NOT MATCH SOURCE - VALIDATE MANUALLY",
			},
		},
	}
	for _, tt := range tests {
		// read testdata file
		data, err := os.ReadFile(filepath.Join("testdata", tt.fields.TestURL))
		assert.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			// Test request parameters
			assert.Equal(t, req.URL.String(), "/"+tt.fields.TestURL)

			// Send response to be tested
			_, err = rw.Write(data)
			assert.NoError(t, err)
		}))

		// initialise Context with test values
		c := getTestContext(t, server)

		c.ApkConvertors[tt.name] = ApkConvertor{
			Apkbuild: &apkbuild.Apkbuild{
				Source: []apkbuild.Source{
					{
						Filename: tt.fields.TestURL,
						Location: server.URL + "/" + tt.fields.TestURL,
					},
				},
				Pkgver: tt.fields.PackageVersion,
				Sha512sums: []apkbuild.SourceHash{
					{
						Source: tt.fields.TestURL,
						Hash:   tt.fields.Sha512},
				},
			},
			GeneratedMelangeConfig: &manifest.GeneratedMelangeConfig{},
		}

		t.Run(tt.name, func(t *testing.T) {
			with := map[string]string{
				"uri":             server.URL + "/" + strings.ReplaceAll(tt.fields.TestURL, tt.fields.PackageVersion, "${{package.version}}"),
				"expected-sha256": tt.fields.ExpectedSha,
			}
			pipeline := config.Pipeline{Uses: "fetch", With: with}

			assert.NoError(t, c.buildFetchStep(context.Background(), c.ApkConvertors[tt.name]))
			assert.Equalf(t, pipeline, c.ApkConvertors[tt.name].GeneratedMelangeConfig.Pipeline[0], "expected sha incorrect")
		})
	}
}

func Test_context_mapconvert(t *testing.T) {
	apkBuild := &apkbuild.Apkbuild{
		Pkgname: "test-pkg",
		Pkgver:  "1.2.3",
		Pkgrel:  "1",
		Pkgdesc: "test package description",
		Url:     "https://foo.com",
		Arch:    []string{"all"},
		License: "MIT",
	}

	tests := []struct {
		name        string
		subPackages []string
		apkBuild    *apkbuild.Apkbuild
	}{
		{
			name: "no_sub_packages",
		},
		{
			name:        "with_unrecognised_sub_packages",
			subPackages: []string{"foo"},
		},
		{
			name:        "with_multi_sub_packages",
			subPackages: []string{"test-pkg-doc", "test-pkg-dev"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subpackages := []apkbuild.Subpackage{}
			for _, subpackage := range tt.subPackages {
				subpackages = append(subpackages, apkbuild.Subpackage{
					Subpkgname: subpackage,
				})
			}

			apkBuild.Subpackages = subpackages

			c := Context{
				NavigationMap: &NavigationMap{
					ApkConvertors: make(map[string]ApkConvertor),
				},
			}
			c.ApkConvertors[tt.name] = ApkConvertor{
				Apkbuild:               apkBuild,
				GeneratedMelangeConfig: &manifest.GeneratedMelangeConfig{},
			}
			c.ApkConvertors[tt.name].mapconvert()

			expected, err := os.ReadFile(filepath.Join("testdata", tt.name+".yaml"))
			assert.NoError(t, err)

			config := c.ApkConvertors[tt.name].GeneratedMelangeConfig
			actual, err := yaml.Marshal(&config)

			assert.NoError(t, err)

			assert.YAMLEqf(t, string(expected), string(actual), "generated convert yaml not the same as expected")
		})
	}
}

func TestMultilineParsing(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "multi_source", "APKBUILD"))
	assert.NoError(t, err)

	key := "icu"

	apkBuildFile := apkbuild.NewApkbuildFile(key, bytes.NewReader(data))
	parsedApkBuild, err := apkbuild.Parse(apkBuildFile, nil)

	assert.NoError(t, err)
	assert.Equal(t, 4, len(parsedApkBuild.Sha512sums))

	assert.Equal(t, "1fd2a20aef48369d1f06e2bb74584877b8ad0eb529320b976264ec2db87420bae242715795f372dbc513ea80047bc49077a064e78205cd5e8b33d746fd2a2912", parsedApkBuild.Sha512sums[0].Hash)
	assert.Equal(t, "05eb134a963a541a280e49e4d0aca07e480fef14daa0108c8fb9add18c150c9d34c8cbc46386c07909d511f7777eb3ea9f494001f191b84a7de0be8047da8b56", parsedApkBuild.Sha512sums[1].Hash)
	assert.Equal(t, "b031e520d41cc313012a0a9d9c4eed51aee9e04213b810bcec32e18d0964f4f26448b989879a9d8901d29024da08ce2ac89c8c6d321c85d78f6414b5edebc1a4", parsedApkBuild.Sha512sums[2].Hash)
	assert.Equal(t, "de2cd008406d133cc838388f5a109560d29323e0a4c8c6306f712a536b6d90846d44bc5f691514621653f33a2929c0d84fa9c54d61d5ddf4606243df63c7e139", parsedApkBuild.Sha512sums[3].Hash)
}

func getTestContext(t *testing.T, server *httptest.Server) Context {
	return Context{
		NavigationMap: &NavigationMap{
			ApkConvertors: make(map[string]ApkConvertor),
		},

		Client: &rlhttp.RLHTTPClient{
			Client: server.Client(),

			// for unit tests we don't need to rate limit requests
			Ratelimiter: rate.NewLimiter(rate.Every(1*time.Second), 20), // 10 request every 10 seconds
		},
		OutDir: t.TempDir(),
	}
}
