// Copyright 2024 Chainguard, Inc.
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

package container

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestBubblewrapCmd(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedArgs string
	}{
		{
			name:         "With default UID and GID",
			config:       new(Config),
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", buildUserID, buildUserID),
		},
		{
			name:         "With config RunAs",
			config:       &Config{RunAsUID: "65535"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "65535"),
		},
		{
			name:         "With config RunAs with distinct UID and GID",
			config:       &Config{RunAsUID: "65535", RunAsGID: "1000"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "1000"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			args := make([]string, 0)

			cmd := new(bubblewrap).cmd(ctx, tt.config, false, nil, args...)
			if cmd.Args == nil {
				t.Fatalf("cmd.Args should not be nil")
			}
			if !strings.Contains(strings.Join(cmd.Args, " "), tt.expectedArgs) {
				t.Fatalf("expected %v, found %v", tt.expectedArgs, cmd.Args)
			}
		})
	}
}

// tarLayer is a v1.Layer that serves only Uncompressed, which is all
// LoadImage reads.
type tarLayer struct {
	v1.Layer
	tarball []byte
}

func (l tarLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.tarball)), nil
}

// usrTarball returns a layer tarball with a single usr/ directory and no entry
// for its own root.
func usrTarball(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}
	return buf.Bytes()
}

// TestBubblewrapLoadImageRootMode verifies that the guest root, which bwrap
// binds as the build environment's /, can be traversed by accounts other than
// its owner, while its parent on the host cannot. The layer has no entry for
// its own root, so only LoadImage can set that mode.
func TestBubblewrapLoadImageRootMode(t *testing.T) {
	for _, umask := range []int{0o022, 0o077} {
		t.Run(fmt.Sprintf("umask %04o", umask), func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			defer syscall.Umask(syscall.Umask(umask))

			loader := &bubblewrapOCILoader{}
			ref, err := loader.LoadImage(t.Context(), tarLayer{tarball: usrTarball(t)}, apko_types.ParseArchitecture("amd64"), nil)
			if err != nil {
				t.Fatalf("LoadImage: %v", err)
			}
			if got := filepath.Base(ref); got != guestRootName {
				t.Errorf("guest root name = %q, want %q", got, guestRootName)
			}
			fi, err := os.Stat(ref)
			if err != nil {
				t.Fatalf("stat guest dir: %v", err)
			}
			if got := fi.Mode().Perm(); got != 0o755 {
				t.Errorf("guest root mode = %04o, want 0755", got)
			}
			if _, err := os.Stat(filepath.Join(ref, "usr")); err != nil {
				t.Errorf("layer entry not extracted under the guest root: %v", err)
			}

			parent := filepath.Dir(ref)
			if loader.guestDir != parent {
				t.Errorf("loader.guestDir = %q, want %q", loader.guestDir, parent)
			}
			fi, err = os.Stat(parent)
			if err != nil {
				t.Fatalf("stat guest parent: %v", err)
			}
			if got := fi.Mode().Perm(); got != 0o700 {
				t.Errorf("guest parent mode = %04o, want 0700", got)
			}

			// A fresh loader, as the build uses, knows only the ref.
			if err := (&bubblewrapOCILoader{}).RemoveImage(t.Context(), ref); err != nil {
				t.Fatalf("RemoveImage: %v", err)
			}
			if _, err := os.Stat(parent); !os.IsNotExist(err) {
				t.Errorf("guest parent still exists after RemoveImage: %v", err)
			}
		})
	}
}

// TestBubblewrapRemoveImageScope verifies that RemoveImage removes the parent
// only for a ref shaped like the one LoadImage returns, and removes any other
// path as given.
func TestBubblewrapRemoveImageScope(t *testing.T) {
	tests := []struct {
		name       string
		parent     string // directory holding the ref, relative to a fresh temp dir
		parentMode os.FileMode
		ref        string // last path element of the ref
		wantParent bool   // whether the parent survives
	}{
		{name: "foreign rootfs", parent: "other", parentMode: 0o700, ref: "rootfs", wantParent: true},
		{name: "same-named parent, not private", parent: "bubblewrap-guest-notes", parentMode: 0o755, ref: "rootfs", wantParent: true},
		{name: "legacy guest dir", parent: "legacy", parentMode: 0o755, ref: "bubblewrap-guest-123", wantParent: true},
		{name: "issued ref", parent: "bubblewrap-guest-123", parentMode: 0o700, ref: "rootfs", wantParent: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, tt.parent)
			ref := filepath.Join(parent, tt.ref)
			if err := os.MkdirAll(ref, 0o755); err != nil {
				t.Fatalf("creating ref: %v", err)
			}
			if err := os.Chmod(parent, tt.parentMode); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}
			sibling := filepath.Join(parent, "sibling")
			if err := os.WriteFile(sibling, nil, 0o600); err != nil {
				t.Fatalf("creating sibling: %v", err)
			}

			if err := (&bubblewrapOCILoader{}).RemoveImage(t.Context(), ref); err != nil {
				t.Fatalf("RemoveImage: %v", err)
			}
			if _, err := os.Stat(ref); !os.IsNotExist(err) {
				t.Errorf("ref still exists: %v", err)
			}
			_, err := os.Stat(sibling)
			if survived := err == nil; survived != tt.wantParent {
				t.Errorf("parent survived = %v, want %v", survived, tt.wantParent)
			}
		})
	}

	t.Run("symlinked parent", func(t *testing.T) {
		base := t.TempDir()
		real := filepath.Join(base, "real")
		if err := os.MkdirAll(filepath.Join(real, "rootfs"), 0o755); err != nil {
			t.Fatalf("creating ref: %v", err)
		}
		link := filepath.Join(base, "bubblewrap-guest-link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatalf("creating symlink: %v", err)
		}

		if err := (&bubblewrapOCILoader{}).RemoveImage(t.Context(), filepath.Join(link, "rootfs")); err != nil {
			t.Fatalf("RemoveImage: %v", err)
		}
		if _, err := os.Stat(filepath.Join(real, "rootfs")); !os.IsNotExist(err) {
			t.Errorf("rootfs behind the symlink still exists: %v", err)
		}
		if _, err := os.Lstat(link); err != nil {
			t.Errorf("symlinked parent was removed: %v", err)
		}
	})

	t.Run("ref that is not clean", func(t *testing.T) {
		base := t.TempDir()
		// base/link points at base/sub/deep, so the kernel resolves
		// base/link/.. to base/sub, while Dir resolves it to base.
		target := filepath.Join(base, "sub", "bubblewrap-guest-1", "rootfs")
		decoy := filepath.Join(base, "bubblewrap-guest-1", "rootfs")
		for _, dir := range []string{target, decoy, filepath.Join(base, "sub", "deep")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("creating %s: %v", dir, err)
			}
		}
		for _, dir := range []string{filepath.Dir(target), filepath.Dir(decoy)} {
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatalf("chmod %s: %v", dir, err)
			}
		}
		if err := os.Symlink(filepath.Join(base, "sub", "deep"), filepath.Join(base, "link")); err != nil {
			t.Fatalf("creating symlink: %v", err)
		}

		ref := base + "/link/../bubblewrap-guest-1/rootfs"
		if err := (&bubblewrapOCILoader{}).RemoveImage(t.Context(), ref); err != nil {
			t.Fatalf("RemoveImage: %v", err)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Errorf("the path the kernel resolves still exists: %v", err)
		}
		if _, err := os.Stat(decoy); err != nil {
			t.Errorf("a different directory was removed: %v", err)
		}
	})

	t.Run("missing ref", func(t *testing.T) {
		if err := (&bubblewrapOCILoader{}).RemoveImage(t.Context(), filepath.Join(t.TempDir(), "gone")); err != nil {
			t.Errorf("RemoveImage on a missing ref: %v", err)
		}
	})
}

// TestBubblewrapCmdBindsGuestRootFirst verifies that the guest root is bound
// as / before any other mount.
func TestBubblewrapCmdBindsGuestRootFirst(t *testing.T) {
	cfg := &Config{
		ImgRef: "/guest/rootfs",
		Mounts: []BindMount{{Source: "/src", Destination: "/work"}},
	}
	args := strings.Join(new(bubblewrap).cmd(slogtest.Context(t), cfg, false, nil).Args, " ")
	root := strings.Index(args, "--bind /guest/rootfs /")
	other := strings.Index(args, "--bind /src /work")
	if root < 0 || other < 0 || root > other {
		t.Errorf("guest root must be bound first, got %q", args)
	}
}
