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

package container

import (
	"strings"
	"testing"
)

func TestParseRootfsFormat(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "unset means apko default", value: "", want: ""},
		{name: "explicit tar means apko default", value: "tar", want: ""},
		{name: "erofs", value: "erofs", want: "erofs"},
		{name: "erofs with compressor", value: "erofs+zstd", want: "erofs+zstd"},
		{name: "erofs with compressor and level", value: "erofs+zstd,level=5", want: "erofs+zstd,level=5"},
		{name: "unknown format rejected", value: "squashfs", wantErr: true},
		{name: "tar compressor rejected", value: "tar+zstd", wantErr: true},
		{name: "erofs prefix without separator rejected", value: "erofsy", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRootfsFormat(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseRootfsFormat(%q) = %q, want error", tt.value, got)
				}
				if !strings.Contains(err.Error(), rootfsFormatEnv) {
					t.Errorf("error %q should name the env var %q", err, rootfsFormatEnv)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRootfsFormat(%q) unexpected error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("parseRootfsFormat(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsErofsFormat(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{"", false},
		{"tar", false},
		{"erofs", true},
		{"erofs+zstd", true},
		{"erofs+lz4hc,level=9", true},
		{"erofsy", false},
		{"not-erofs", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := isErofsFormat(tt.format); got != tt.want {
				t.Errorf("isErofsFormat(%q) = %v, want %v", tt.format, got, tt.want)
			}
		})
	}
}

func TestQemuRootfsFormatFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "unset", value: "", want: ""},
		{name: "erofs", value: "erofs", want: "erofs"},
		// createMicroVM surfaces the error; the loader must not hand apko a
		// value apko would reject.
		{name: "invalid falls back to default", value: "squashfs", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(rootfsFormatEnv, tt.value)
			if got := qemuRootfsFormat(); got != tt.want {
				t.Errorf("qemuRootfsFormat() = %q, want %q", got, tt.want)
			}
			if got := (qemuOCILoader{}).LayerFormat(); got != tt.want {
				t.Errorf("qemuOCILoader.LayerFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRootfsBlockdevArg(t *testing.T) {
	const imgRef = "/tmp/melange-guest-123.img"

	tar := rootfsBlockdevArg(imgRef, "")
	if strings.Contains(tar, "read-only") {
		t.Errorf("tar rootfs must stay writable, the guest init unpacks onto it: %q", tar)
	}
	if !strings.HasSuffix(tar, "file.filename="+imgRef) {
		t.Errorf("blockdev arg %q should end with the image path", tar)
	}

	for _, format := range []string{"erofs", "erofs+zstd"} {
		got := rootfsBlockdevArg(imgRef, format)
		if !strings.Contains(got, "read-only=on") {
			t.Errorf("rootfsBlockdevArg(_, %q) = %q, want read-only=on", format, got)
		}
		if !strings.Contains(got, "node-name="+rootfsBlockdevNode) {
			t.Errorf("rootfsBlockdevArg(_, %q) = %q, want node-name=%s", format, got, rootfsBlockdevNode)
		}
	}
}

func TestCacheOverlayCommand(t *testing.T) {
	// With a tar rootfs /mount is the bare scratch disk and is a valid
	// overlayfs upperdir.
	tar := cacheOverlayCommand("")
	if !strings.Contains(tar, "upperdir=/mount/cache-upper") {
		t.Errorf("tar rootfs should overlay onto /mount, got: %q", tar)
	}

	// With an EROFS rootfs /mount is itself an overlay. overlayfs refuses an
	// upperdir on an overlay, so it has to land on the bare scratch disk.
	for _, format := range []string{"erofs", "erofs+zstd"} {
		got := cacheOverlayCommand(format)
		if !strings.Contains(got, "upperdir="+scratchDiskMount+"/cache-upper") {
			t.Errorf("cacheOverlayCommand(%q) upperdir must be on %s, got: %q", format, scratchDiskMount, got)
		}
		if !strings.Contains(got, "workdir="+scratchDiskMount+"/cache-work") {
			t.Errorf("cacheOverlayCommand(%q) workdir must be on %s, got: %q", format, scratchDiskMount, got)
		}
		if strings.Contains(got, "upperdir=/mount/") {
			t.Errorf("cacheOverlayCommand(%q) must not put upperdir on the overlay: %q", format, got)
		}
	}
}

func TestGuestLayerFormat(t *testing.T) {
	// A loader that does not implement LayerFormatter gets apko's default.
	if got := GuestLayerFormat(&bubblewrapOCILoader{}); got != "" {
		t.Errorf("GuestLayerFormat(bubblewrap) = %q, want %q", got, "")
	}

	t.Setenv(rootfsFormatEnv, "erofs")
	if got := GuestLayerFormat(qemuOCILoader{}); got != "erofs" {
		t.Errorf("GuestLayerFormat(qemu) = %q, want %q", got, "erofs")
	}

	t.Setenv(rootfsFormatEnv, "")
	if got := GuestLayerFormat(qemuOCILoader{}); got != "" {
		t.Errorf("GuestLayerFormat(qemu) with unset env = %q, want %q", got, "")
	}
}
