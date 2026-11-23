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
			if !isGuestRoot(ref) {
				t.Errorf("isGuestRoot(%q) = false for a ref LoadImage returned", ref)
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

// TestIsGuestRoot verifies that isGuestRoot accepts only the shape LoadImage
// returns, and rejects every other path so that RemoveImage removes it as
// given.
func TestIsGuestRoot(t *testing.T) {
	// dir creates rel under base with the given mode and returns its path. The
	// mode is restored on cleanup so that t.TempDir can remove the tree.
	dir := func(t *testing.T, base, rel string, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(base, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("creating %s: %v", p, err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o700) })
		return p
	}
	// guest creates a bubblewrap-guest-1 directory with the given mode that
	// holds a rootfs, and returns the rootfs path.
	guest := func(mode os.FileMode) func(*testing.T, string) string {
		return func(t *testing.T, base string) string {
			t.Helper()
			parent := dir(t, base, "bubblewrap-guest-1", 0o755)
			root := dir(t, parent, "rootfs", 0o755)
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatalf("chmod %s: %v", parent, err)
			}
			return root
		}
	}
	// at creates a rootfs at rel under base, in a parent that is a private
	// directory, and returns the path to hand to isGuestRoot, built by build.
	at := func(rel string, build func(base, root string) string) func(*testing.T, string) string {
		return func(t *testing.T, base string) string {
			t.Helper()
			root := dir(t, base, rel, 0o755)
			if err := os.Chmod(filepath.Dir(root), 0o700); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}
			return build(base, root)
		}
	}
	same := func(_, root string) string { return root }

	tests := []struct {
		name  string
		setup func(t *testing.T, base string) string
		want  bool
	}{
		// The shape LoadImage returns.
		{name: "issued shape", setup: guest(0o700), want: true},
		{name: "issued shape in a setgid temp dir", setup: guest(0o700 | os.ModeSetgid), want: true},
		{name: "name with a space", setup: at("bubblewrap-guest-a b/rootfs", same), want: true},
		{name: "rootfs missing, parent present", setup: func(t *testing.T, base string) string {
			return filepath.Join(dir(t, base, "bubblewrap-guest-1", 0o700), "rootfs")
		}, want: true},
		{name: "temp dir reached through a symlink", setup: func(t *testing.T, base string) string {
			real := dir(t, base, "real", 0o755)
			if err := os.Symlink(real, filepath.Join(base, "tmp")); err != nil {
				t.Fatalf("creating symlink: %v", err)
			}
			dir(t, real, "bubblewrap-guest-1/rootfs", 0o755)
			if err := os.Chmod(filepath.Join(real, "bubblewrap-guest-1"), 0o700); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}
			return filepath.Join(base, "tmp", "bubblewrap-guest-1", "rootfs")
		}, want: true},

		// The parent has the right name but the wrong mode.
		{name: "parent 0755", setup: guest(0o755), want: false},
		{name: "parent 0750", setup: guest(0o750), want: false},
		{name: "parent 0770", setup: guest(0o770), want: false},
		{name: "parent 0777", setup: guest(0o777), want: false},
		{name: "parent 0701", setup: guest(0o701), want: false},
		{name: "parent 0600", setup: guest(0o600), want: false},
		{name: "parent 0500", setup: guest(0o500), want: false},
		{name: "parent 0300", setup: guest(0o300), want: false},
		{name: "parent 0000", setup: guest(0), want: false},

		// The parent is not a real directory.
		{name: "parent is a symlink to a private dir", setup: func(t *testing.T, base string) string {
			real := dir(t, base, "real", 0o700)
			dir(t, real, "rootfs", 0o755)
			if err := os.Symlink(real, filepath.Join(base, "bubblewrap-guest-link")); err != nil {
				t.Fatalf("creating symlink: %v", err)
			}
			return filepath.Join(base, "bubblewrap-guest-link", "rootfs")
		}},
		{name: "parent is a dangling symlink", setup: func(t *testing.T, base string) string {
			if err := os.Symlink(filepath.Join(base, "gone"), filepath.Join(base, "bubblewrap-guest-1")); err != nil {
				t.Fatalf("creating symlink: %v", err)
			}
			return filepath.Join(base, "bubblewrap-guest-1", "rootfs")
		}},
		{name: "parent is a regular file", setup: func(t *testing.T, base string) string {
			if err := os.WriteFile(filepath.Join(base, "bubblewrap-guest-1"), nil, 0o700); err != nil {
				t.Fatalf("creating file: %v", err)
			}
			return filepath.Join(base, "bubblewrap-guest-1", "rootfs")
		}},
		{name: "parent does not exist", setup: func(_ *testing.T, base string) string {
			return filepath.Join(base, "bubblewrap-guest-1", "rootfs")
		}},
		{name: "nothing exists and the parent is not named", setup: func(_ *testing.T, base string) string {
			return filepath.Join(base, "other", "rootfs")
		}},

		// The parent name is wrong.
		{name: "parent without the prefix", setup: at("other/rootfs", same)},
		{name: "prefix without the dash", setup: at("bubblewrap-guest/rootfs", same)},
		{name: "prefix in a different case", setup: at("Bubblewrap-guest-1/rootfs", same)},
		{name: "prefix not at the start", setup: at("x-bubblewrap-guest-1/rootfs", same)},
		{name: "prefix as a grandparent", setup: at("bubblewrap-guest-1/sub/rootfs", same)},
		{name: "rootfs inside rootfs", setup: at("bubblewrap-guest-1/rootfs/rootfs", same)},

		// The last element is wrong.
		{name: "other name", setup: at("bubblewrap-guest-1/other", same)},
		{name: "rootfs with a suffix", setup: at("bubblewrap-guest-1/rootfs2", same)},
		{name: "rootfs with an extension", setup: at("bubblewrap-guest-1/rootfs.bak", same)},
		{name: "rootfs in a different case", setup: at("bubblewrap-guest-1/Rootfs", same)},
		{name: "path below rootfs", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string {
			return filepath.Join(root, "usr")
		})},
		{name: "legacy ref, the guest dir itself", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string {
			return filepath.Dir(root)
		})},

		// The path is not clean.
		{name: "trailing slash", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string { return root + "/" })},
		{name: "trailing dot", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string { return root + "/." })},
		{name: "trailing dotdot", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string { return root + "/.." })},
		{name: "doubled slash", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string {
			return filepath.Join(filepath.Dir(root), "") + "//rootfs"
		})},
		{name: "dot element", setup: at("bubblewrap-guest-1/rootfs", func(_, root string) string {
			return filepath.Dir(root) + "/./rootfs"
		})},
		{name: "dotdot element", setup: at("bubblewrap-guest-1/rootfs", func(base, _ string) string {
			return base + "/x/../bubblewrap-guest-1/rootfs"
		})},
		{name: "dotdot through a symlink", setup: func(t *testing.T, base string) string {
			dir(t, base, "sub/deep", 0o755)
			dir(t, base, "bubblewrap-guest-1/rootfs", 0o755)
			if err := os.Chmod(filepath.Join(base, "bubblewrap-guest-1"), 0o700); err != nil {
				t.Fatalf("chmod parent: %v", err)
			}
			if err := os.Symlink(filepath.Join(base, "sub", "deep"), filepath.Join(base, "link")); err != nil {
				t.Fatalf("creating symlink: %v", err)
			}
			return base + "/link/../bubblewrap-guest-1/rootfs"
		}},
		{name: "NUL byte in the parent name", setup: func(_ *testing.T, base string) string {
			return base + "/bubblewrap-guest-1\x00/rootfs"
		}},

		// Degenerate refs.
		{name: "empty", setup: func(*testing.T, string) string { return "" }},
		{name: "dot", setup: func(*testing.T, string) string { return "." }},
		{name: "dotdot", setup: func(*testing.T, string) string { return ".." }},
		{name: "root", setup: func(*testing.T, string) string { return "/" }},
		{name: "bare rootfs", setup: func(*testing.T, string) string { return "rootfs" }},
		{name: "absolute rootfs at the root", setup: func(*testing.T, string) string { return "/rootfs" }},
		{name: "dot rootfs", setup: func(*testing.T, string) string { return "./rootfs" }},
		{name: "dotdot rootfs", setup: func(*testing.T, string) string { return "../rootfs" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := tt.setup(t, t.TempDir())
			if got := isGuestRoot(ref); got != tt.want {
				t.Errorf("isGuestRoot(%q) = %v, want %v", ref, got, tt.want)
			}
		})
	}

	t.Run("relative issued shape", func(t *testing.T) {
		base := t.TempDir()
		guest(0o700)(t, base)
		t.Chdir(base)
		if !isGuestRoot("bubblewrap-guest-1/rootfs") {
			t.Error("a clean relative ref with the issued shape did not match")
		}
	})

	t.Run("relative lookalike", func(t *testing.T) {
		base := t.TempDir()
		guest(0o755)(t, base)
		t.Chdir(base)
		if isGuestRoot("bubblewrap-guest-1/rootfs") {
			t.Error("a relative ref under a 0755 parent matched")
		}
	})
}
