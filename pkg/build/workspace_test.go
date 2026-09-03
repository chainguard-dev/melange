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

package build

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
)

// tarRunner is a container.Runner that only implements WorkspaceTar, returning
// a canned tar stream.
type tarRunner struct {
	tarball []byte
}

func (t *tarRunner) WorkspaceTar(context.Context, *container.Config, []string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(t.tarball)), nil
}

func (t *tarRunner) Close() error                                      { return nil }
func (t *tarRunner) Name() string                                      { return "tar-runner" }
func (t *tarRunner) TestUsability(context.Context) bool                { return true }
func (t *tarRunner) OCIImageLoader() container.Loader                  { return nil }
func (t *tarRunner) StartPod(context.Context, *container.Config) error { return nil }
func (t *tarRunner) Run(context.Context, *container.Config, map[string]string, ...string) error {
	return nil
}
func (t *tarRunner) TerminatePod(context.Context, *container.Config) error { return nil }
func (t *tarRunner) TempDir() string                                       { return "" }
func (t *tarRunner) GetReleaseData(context.Context, *container.Config) (*apko_build.ReleaseData, error) {
	return nil, nil
}

var _ container.Runner = (*tarRunner)(nil)

// TestRetrieveWorkspaceSpecialModeBits verifies that setuid, setgid and sticky
// bits survive the trip through retrieveWorkspace. Regression test for
// https://github.com/chainguard-dev/melange/issues/2642, where directories
// were created with Mode().Perm() and nothing set the special bits after.
func TestRetrieveWorkspaceSpecialModeBits(t *testing.T) {
	entries := []struct {
		name     string
		typeflag byte
		mode     int64
	}{
		{"melange-out/pkg/", tar.TypeDir, 0o755},
		{"melange-out/pkg/tmp/", tar.TypeDir, 0o1777},
		{"melange-out/pkg/var/", tar.TypeDir, 0o755},
		{"melange-out/pkg/var/tmp/", tar.TypeDir, 0o1777},
		{"melange-out/pkg/usr/", tar.TypeDir, 0o755},
		{"melange-out/pkg/usr/mail/", tar.TypeDir, 0o2755},
		{"melange-out/pkg/usr/setuid-dir/", tar.TypeDir, 0o4755},
		{"melange-out/pkg/usr/postdrop", tar.TypeReg, 0o2755},
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
		}); err != nil {
			t.Fatalf("writing header %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}

	ctx := context.Background()
	workspaceDir := t.TempDir()
	b := &Build{
		Configuration: &config.Configuration{},
		WorkspaceDir:  workspaceDir,
		Runner:        &tarRunner{tarball: buf.Bytes()},
	}
	fsys := apkofs.DirFS(ctx, workspaceDir)

	if err := b.retrieveWorkspace(ctx, fsys); err != nil {
		t.Fatalf("retrieveWorkspace: %v", err)
	}

	for _, e := range entries {
		// Let archive/tar do the mode conversion, so the expectation is in
		// terms of os.ModeSetuid/Setgid/Sticky rather than raw octal.
		hdr := tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode}
		want := hdr.FileInfo().Mode() & (os.ModePerm | specialModeBits)

		fi, err := fsys.Stat(e.name)
		if err != nil {
			t.Errorf("stat %s: %v", e.name, err)
			continue
		}
		if got := fi.Mode() & (os.ModePerm | specialModeBits); got != want {
			t.Errorf("%s: got mode %v (%04o), want %v (%04o)", e.name, got, got.Perm(), want, want.Perm())
		}
	}
}
