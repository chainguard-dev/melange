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
	"context"
	"os"
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
