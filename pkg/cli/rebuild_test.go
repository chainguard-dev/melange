// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	purl "github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
)

// RebuildOptions is exported so flags can be parsed outside RebuildCmd; it
// must work for callers that never go through RebuildCmd.
func TestRebuildOptions_OutsideRebuildCmd(t *testing.T) {
	ctx := context.Background()
	pkginfo := &goapk.PackageInfo{Name: "hello", Origin: "hello"}
	cfg := &config.Configuration{Package: config.Package{Name: "hello"}}
	cfgpkg := &spdx.Package{}
	cfgpurl := purl.PackageURL{Namespace: "wolfi-dev", Name: "os", Subpath: "hello.yaml"}

	t.Run("no source dir starts from an empty one", func(t *testing.T) {
		flags, _, err := ParseRebuildFlags([]string{"--runner=bubblewrap"})
		require.NoError(t, err)

		opts, err := flags.RebuildOptions(ctx, pkginfo, cfg, cfgpkg, cfgpurl)
		require.NoError(t, err)

		b := &build.Build{}
		for _, opt := range opts {
			require.NoError(t, opt(b))
		}
		require.NotEmpty(t, b.SourceDir)
		require.NotEqual(t, ".", b.SourceDir)
		t.Cleanup(func() { os.RemoveAll(b.SourceDir) })
		entries, err := os.ReadDir(b.SourceDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	})

	t.Run("source dir is passed through", func(t *testing.T) {
		dir := t.TempDir()
		flags, _, err := ParseRebuildFlags([]string{"--runner=bubblewrap", "--source-dir=" + dir})
		require.NoError(t, err)

		opts, err := flags.RebuildOptions(ctx, pkginfo, cfg, cfgpkg, cfgpurl)
		require.NoError(t, err)

		b := &build.Build{}
		for _, opt := range opts {
			require.NoError(t, opt(b))
		}
		require.Equal(t, dir, b.SourceDir)
	})

	t.Run("source package points at RebuildCmd", func(t *testing.T) {
		flags, _, err := ParseRebuildFlags([]string{"--runner=bubblewrap", "--source-package=hello-source-1-r0.apk"})
		require.NoError(t, err)

		_, err = flags.RebuildOptions(ctx, pkginfo, cfg, cfgpkg, cfgpurl)
		require.ErrorContains(t, err, "use RebuildCmd")
	})
}

// RebuildCmd removes its working directory when it returns, so it must not
// leave the flags pointing at it.
func TestRebuildCmd_RestoresWorkDir(t *testing.T) {
	flags, _, err := ParseRebuildFlags(nil)
	require.NoError(t, err)

	require.NoError(t, RebuildCmd(context.Background(), flags, nil))
	require.Empty(t, flags.workDir)
}

// A rebuild takes its sources from the cache of its --source-package, so the
// flag has to reach the Build the rebuild runs.
func TestRebuildOptions_StrictSourcesFromCache(t *testing.T) {
	ctx := context.Background()
	pkginfo := &goapk.PackageInfo{Name: "hello", Origin: "hello"}
	cfg := &config.Configuration{Package: config.Package{Name: "hello"}}
	cfgpurl := purl.PackageURL{Namespace: "wolfi-dev", Name: "os", Subpath: "hello.yaml"}

	// The smallest companion that verifies: one empty manifest, which pins to
	// itself.
	companion := filepath.Join(t.TempDir(), "hello-source-1-r0.apk")
	f, err := os.Create(companion)
	require.NoError(t, err)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "usr/src/hello/SOURCES.sha256", Typeflag: tar.TypeReg, Mode: 0o644}))
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())

	for _, tt := range []struct {
		value   string
		want    []string
		wantErr string
	}{
		{value: "git-checkout", want: []string{"git-checkout"}},
		{value: "Git-Checkout", wantErr: `unknown step kind "Git-Checkout"`},
	} {
		flags, _, err := ParseRebuildFlags([]string{"--runner=bubblewrap", "--source-package=" + companion, "--strict-sources-from-cache=" + tt.value})
		require.NoError(t, err)
		flags.workDir = t.TempDir()

		opts, err := flags.rebuildOptions(ctx, pkginfo, cfg, &spdx.Package{}, cfgpurl, []byte{})
		require.NoError(t, err, tt.value)

		b := &build.Build{}
		var applyErr error
		for _, opt := range opts {
			applyErr = errors.Join(applyErr, opt(b))
		}
		if tt.wantErr != "" {
			require.ErrorContains(t, applyErr, tt.wantErr)
			continue
		}
		require.NoError(t, applyErr)
		require.Equal(t, tt.want, b.StrictSourcesFromCache)
	}
}
