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

package sca

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"

	"chainguard.dev/melange/pkg/config"
)

// mapSCAFS adapts an fstest.MapFS to SCAFS.
type mapSCAFS struct{ fstest.MapFS }

func (m mapSCAFS) Readlink(name string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
}

// fsHandle is an SCAHandle over an in-memory filesystem.
type fsHandle struct {
	name, version string
	fsys          mapSCAFS
}

func (h *fsHandle) PackageName() string     { return h.name }
func (h *fsHandle) RelativeNames() []string { return []string{h.name} }
func (h *fsHandle) Version() string         { return h.version }
func (h *fsHandle) FilesystemForRelative(string) (SCAFS, error) {
	return h.fsys, nil
}
func (h *fsHandle) Filesystem() (SCAFS, error)            { return h.fsys, nil }
func (h *fsHandle) Options() config.PackageOption         { return config.PackageOption{} }
func (h *fsHandle) BaseDependencies() config.Dependencies { return config.Dependencies{} }
func (h *fsHandle) InstalledPackages() map[string]string  { return map[string]string{} }
func (h *fsHandle) PkgResolver() *apk.PkgResolver         { return nil }

// TestPkgConfigRequires checks the pc: runtime dependencies generated from
// the Requires, Requires.private and Requires.internal lines of .pc files,
// in the forms real -dev packages ship: comma separated, space separated,
// with and without version constraints and comparison operators.
func TestPkgConfigRequires(t *testing.T) {
	ctx := slogtest.Context(t)

	// Modeled on glib's gio-2.0.pc.
	gio := `prefix=/usr
libdir=${prefix}/lib
includedir=${prefix}/include

Name: GIO
Description: glib I/O library
Version: 2.82.4
Requires: glib-2.0, gobject-2.0
Requires.private: gmodule-no-export-2.0 >= 2.82.4, zlib, mount >= 2.23
Libs: -L${libdir} -lgio-2.0
Cflags: -I${includedir}
`
	// Modeled on openssl's openssl.pc: space separated, no versions.
	openssl := `prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: OpenSSL
Description: Secure Sockets Layer and cryptography libraries and tools
Version: 3.4.0
Requires: libssl libcrypto
`
	// Modeled on libcurl.pc: no spaces after commas.
	curl := `prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: libcurl
URL: https://curl.se/
Description: Library to transfer files with HTTP, FTP, etc.
Version: 8.11.1
Requires.private: libidn2,zlib,libssl,libcrypto
Libs: -L${libdir} -lcurl
Cflags: -I${includedir}
`
	// The comparison operators real .pc files use, and Requires.internal.
	ops := `prefix=/usr

Name: ops
Description: comparison operators
Version: 1.0.0
Requires: a = 1.0, c < 3.0
Requires.private: d <= 4.0, e > 5.0, f >= 6.0
Requires.internal: g
`
	// A vendored .pc file only adds a vendored provide, never a runtime
	// dependency, even when it has Requires lines.
	vendored := `prefix=/opt/vendored

Name: vendored
Description: vendored library
Version: 9.9.9
Requires: should-not-appear
`

	h := &fsHandle{
		name:    "test-dev",
		version: "1.0.0-r0",
		fsys: mapSCAFS{fstest.MapFS{
			"usr/lib/pkgconfig/gio-2.0.pc":         {Data: []byte(gio)},
			"usr/lib/pkgconfig/openssl.pc":         {Data: []byte(openssl)},
			"usr/lib/pkgconfig/libcurl.pc":         {Data: []byte(curl)},
			"usr/share/pkgconfig/ops.pc":           {Data: []byte(ops)},
			"opt/vendored/lib/pkgconfig/vendor.pc": {Data: []byte(vendored)},
		}},
	}

	got := config.Dependencies{}
	if err := generatePkgConfigDeps(ctx, h, &got, nil); err != nil {
		t.Fatal(err)
	}

	// fs.WalkDir visits files in lexical order.
	want := config.Dependencies{
		Runtime: []string{
			// usr/lib/pkgconfig/gio-2.0.pc
			"pc:glib-2.0",
			"pc:gobject-2.0",
			"pc:gmodule-no-export-2.0",
			"pc:zlib",
			"pc:mount",
			// usr/lib/pkgconfig/libcurl.pc
			"pc:libidn2",
			"pc:zlib",
			"pc:libssl",
			"pc:libcrypto",
			// usr/lib/pkgconfig/openssl.pc
			"pc:libssl",
			"pc:libcrypto",
			// usr/share/pkgconfig/ops.pc
			"pc:a",
			"pc:c",
			"pc:d",
			"pc:e",
			"pc:f",
			"pc:g",
		},
		Provides: []string{
			"pc:gio-2.0=1.0.0-r0",
			"pc:libcurl=1.0.0-r0",
			"pc:openssl=1.0.0-r0",
			"pc:ops=1.0.0-r0",
		},
		Vendored: []string{
			"pc:vendor=1.0.0-r0",
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("generatePkgConfigDeps(): (-want, +got):\n%s", diff)
	}
}
