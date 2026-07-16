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
	"slices"
	"strings"
	"testing"
)

func TestIsolationPaths(t *testing.T) {
	iso := &Isolation{ID: "deadbeef", SubpkgName: "foo-dev"}

	if got, want := iso.BaseDir(), "/tmp/parallel-build-deadbeef"; got != want {
		t.Errorf("BaseDir() = %q, want %q", got, want)
	}
	if got, want := iso.ChrootDir(), "/tmp/parallel-build-deadbeef/root"; got != want {
		t.Errorf("ChrootDir() = %q, want %q", got, want)
	}
	if got, want := iso.OutDir(), "/tmp/parallel-build-deadbeef/out"; got != want {
		t.Errorf("OutDir() = %q, want %q", got, want)
	}
}

func TestNewIsolationIDUnique(t *testing.T) {
	a, err := NewIsolationID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewIsolationID()
	if err != nil {
		t.Fatal(err)
	}
	if a == "" || a == b {
		t.Errorf("expected two distinct non-empty ids, got %q and %q", a, b)
	}
}

func TestQemuIsolationSetupScript(t *testing.T) {
	iso := &Isolation{ID: "abc123", SubpkgName: "foo-dev"}
	script := qemuIsolationSetupScript(iso)

	wantSubstrings := []string{
		"set -e",
		// overlay for /home/build backed by the private tmpfs upper layer.
		"lowerdir=/mount/home/build,upperdir=/mount/tmp/parallel-build-abc123/tmp/upper,workdir=/mount/tmp/parallel-build-abc123/tmp/work",
		// read-only bind of the shared melange-out.
		"mount --bind /mount/home/build/melange-out /mount/tmp/parallel-build-abc123/root/home/build/melange-out",
		"mount -o remount,ro,bind /mount/tmp/parallel-build-abc123/root/home/build/melange-out",
		// read-write bind of this subpackage's private out dir.
		"mount --bind /mount/tmp/parallel-build-abc123/out /mount/tmp/parallel-build-abc123/root/home/build/melange-out/foo-dev",
		// private /tmp.
		"mount -t tmpfs tmpfs /mount/tmp/parallel-build-abc123/root/tmp",
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(script, s) {
			t.Errorf("setup script missing %q\nfull script:\n%s", s, script)
		}
	}
}

func TestQemuIsolationCopyOutScript(t *testing.T) {
	iso := &Isolation{ID: "abc123", SubpkgName: "foo-dev"}
	script := qemuIsolationCopyOutScript(iso, "build")

	for _, s := range []string{
		"cp -a /mount/tmp/parallel-build-abc123/out/. /mount/home/build/melange-out/foo-dev/",
		"chown -R build /mount/home/build/melange-out/foo-dev",
	} {
		if !strings.Contains(script, s) {
			t.Errorf("copyout script missing %q\nfull script:\n%s", s, script)
		}
	}

	// With no user, no chown line is emitted.
	if strings.Contains(qemuIsolationCopyOutScript(iso, ""), "chown") {
		t.Errorf("expected no chown when user is empty")
	}
}

func TestQemuIsolationTeardownScript(t *testing.T) {
	iso := &Isolation{ID: "abc123", SubpkgName: "foo-dev"}
	script := qemuIsolationTeardownScript(iso)

	for _, s := range []string{
		"umount -R /mount/tmp/parallel-build-abc123/root",
		"rm -rf /mount/tmp/parallel-build-abc123",
	} {
		if !strings.Contains(script, s) {
			t.Errorf("teardown script missing %q\nfull script:\n%s", s, script)
		}
	}
}

func TestBubblewrapIsolationArgs(t *testing.T) {
	cfg := &Config{
		WorkspaceDir: "/host/ws",
		Isolation:    &Isolation{ID: "abc123", SubpkgName: "foo-dev"},
	}
	args := bubblewrapIsolationArgs(cfg)

	// overlay lower is the shared workspace, dest is /home/build.
	if i := slices.Index(args, "--overlay-src"); i < 0 || args[i+1] != "/host/ws" {
		t.Errorf("expected --overlay-src /host/ws, got %v", args)
	}
	if i := slices.Index(args, "--overlay"); i < 0 || args[i+3] != DefaultWorkspaceDir {
		t.Errorf("expected --overlay ... %s, got %v", DefaultWorkspaceDir, args)
	}
	// melange-out is a read-only bind.
	if i := slices.Index(args, "--ro-bind"); i < 0 || args[i+1] != "/host/ws/melange-out" {
		t.Errorf("expected --ro-bind /host/ws/melange-out, got %v", args)
	}
	// subpackage out dir is a read-write bind onto melange-out/<subpkg>.
	if i := slices.Index(args, "--bind"); i < 0 || args[i+2] != "/home/build/melange-out/foo-dev" {
		t.Errorf("expected --bind onto /home/build/melange-out/foo-dev, got %v", args)
	}
}
