// Copyright 2025 Chainguard, Inc.
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

//go:generate go run ./../../ build --generate-index=false --out-dir=./testdata/generated ./testdata/linux.yaml --arch=x86_64
//go:generate go run ./../../ build --generate-index=false --out-dir=./testdata/generated ./testdata/linux-rpi.yaml --arch=x86_64

// linux-rpi actually produces aarch64 binaries regardless of arch but it's just
// testdata and works either way so I don't think that detail matters.

package sca

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"

	"chainguard.dev/melange/pkg/config"
)

func TestKernelSca(t *testing.T) {
	ctx := slogtest.Context(t)

	for _, tc := range []struct {
		apk    string
		yaml   string
		expect config.Dependencies
		name   string
	}{
		{
			name:   "bzimage",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-bzimage-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "vmlinux",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-vmlinux-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "gzipped-vmlinux",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-gzipped-vmlinux-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "uki",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-uki-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-gzipped",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-gzip-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-zstd",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-zstd-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-xz",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-xz-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "rpi-kernel",
			yaml:   "linux-rpi.yaml",
			apk:    "generated/x86_64/linux-rpi-1.20250915-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.12.25", "linux:6.12.25-v7", "linux:6.12.25-v7l", "linux:6.12.25-v8", "linux:6.12.25-v8-16k"}},
		},
		{
			name:   "rpi-modules",
			yaml:   "linux-rpi.yaml",
			apk:    "generated/x86_64/linux-rpi-modules-1.20250915-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.12.25", "linux:6.12.25-v7", "linux:6.12.25-v7l", "linux:6.12.25-v8", "linux:6.12.25-v8-16k"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th := handleFromApk(ctx, t, tc.apk, tc.yaml)
			defer th.exp.Close()

			got := config.Dependencies{}
			if err := Analyze(ctx, th, &got); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Errorf("Analyze(): (-want, +got):\n%s", diff)
			}
		})
	}
}

// mapSCAFS adds the Readlink method of SCAFS to fstest.MapFS.
type mapSCAFS struct {
	fstest.MapFS
}

func (m mapSCAFS) Readlink(name string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
}

// fsHandle serves a fixed filesystem. generateKernelDeps calls no other
// SCAHandle method.
type fsHandle struct {
	SCAHandle
	fsys SCAFS
}

func (h fsHandle) Filesystem() (SCAFS, error) {
	return h.fsys, nil
}

func TestKernelScaOnlyModuleFiles(t *testing.T) {
	ctx := slogtest.Context(t)

	// An initramfs built by dracut-ng 113 or later starts with an
	// uncompressed cpio of the compressed modules. Their zstd data can
	// hold "vermagic=" followed by a truncated version.
	initramfs := []byte("070701...kernel/uio.ko.zst\x28\xb5\x2f\xfdvermagic=6.17.7-te\x00")

	h := fsHandle{fsys: mapSCAFS{fstest.MapFS{
		"usr/lib/modules/6.17.7-test/kernel/uio.ko":   {Data: []byte("\x7fELFvermagic=6.17.7-test SMP mod_unload\x00")},
		"usr/lib/modules/6.17.7-test/initramfs.img":   {Data: initramfs},
		"usr/lib/modules/6.17.7-test/modules.builtin": {Data: []byte("vermagic=bogus\n")},
	}}}

	got := config.Dependencies{}
	if err := generateKernelDeps(ctx, h, &got, nil); err != nil {
		t.Fatal(err)
	}

	want := config.Dependencies{Runtime: []string{"linux:6.17.7-test"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("generateKernelDeps(): (-want, +got):\n%s", diff)
	}
}

func TestIsKernelModule(t *testing.T) {
	for path, want := range map[string]bool{
		"usr/lib/modules/6.17.7/kernel/uio.ko":     true,
		"usr/lib/modules/6.17.7/kernel/uio.ko.gz":  true,
		"usr/lib/modules/6.17.7/kernel/uio.ko.xz":  true,
		"usr/lib/modules/6.17.7/kernel/uio.ko.zst": true,
		"usr/lib/modules/6.17.7/kernel/uio.ko.bz2": false,
		"usr/lib/modules/6.17.7/initramfs.img":     false,
		"usr/lib/modules/6.17.7/vmlinuz":           false,
		"usr/lib/modules/6.17.7/modules.dep":       false,
		"usr/lib/modules/6.17.7/kernel/uio.kobj":   false,
	} {
		if got := isKernelModule(path); got != want {
			t.Errorf("isKernelModule(%q) = %v, want %v", path, got, want)
		}
	}
}
