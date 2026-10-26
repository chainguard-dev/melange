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

package license

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/license/detect"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-cmp/cmp"

	"chainguard.dev/melange/pkg/config"
)

func TestFindLicenseFiles(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		"LICENSE",
		"LICENSE.md",
		"COPYING",
		"COPYING.txt",
		"random.txt",
		"LICENSE-MIT.md",
		"README.md",
		"LICENSE-APACHE",
		"LICENSE.gemspec",
		"COPYRIGHT",
		"MIT-COPYING",
		"copyme",
		"COPY",
		"LICENSE.txt",
	}

	for _, name := range testFiles {
		filePath := filepath.Join(tmpDir, name)
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp.Close()
	}

	tmpFS := apkofs.DirFS(t.Context(), tmpDir)

	// Call function under test
	licenseFiles, err := FindLicenseFiles(tmpFS, true)
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
	}

	for _, file := range licenseFiles {
		t.Logf("Found license file: %s", file.Name)
	}

	// Verify the results
	// The order of the expected licenses is important, but not strictly checked
	expectedFiles := []string{
		"LICENSE",
		"LICENSE.md",
		"LICENSE.txt",
		"COPYING",
		"COPYRIGHT",
		"COPYING.txt",
		"LICENSE-APACHE",
		"LICENSE-MIT.md",
		"MIT-COPYING",
	}
	if len(licenseFiles) != len(expectedFiles) {
		t.Errorf("Expected %d license files, got %d", len(expectedFiles), len(licenseFiles))
	}

	var found bool
	for _, expected := range expectedFiles {
		found = false
		for _, l := range licenseFiles {
			if l.Name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license file %s not found", expected)
		}
	}

	testInoreFiles := []string{
		"node_modules/LICENSE",
		"node_modules/LICENSE.md",
		"venv/COPYING",
		"venv/COPYING.txt",
		"venv/random.txt",
		"env/LICENSE-MIT.md",
		"env/README.md",
		"env/LICENSE-APACHE",
		".virtualenv/LICENSE.gemspec",
		".virtualenv/COPYRIGHT",
		".virtualenv/MIT-COPYING",
		"node_modules/copyme",
		"node_modules/COPY",
		"node_modules/LICENSE.txt",
		"rust-src-1.86.0/rust-src/foo/LICENSE-MIT",
		"rustc-src-1.86.0/rust-src/foo/LICENSE-MIT",
	}

	tmpDir = t.TempDir()
	for _, name := range testInoreFiles {
		filePath := filepath.Join(tmpDir, name)
		err := os.MkdirAll(filepath.Join(tmpDir, filepath.Dir(name)), os.ModePerm)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", name, err)
		}
		fp.Close()
	}

	tmpFS = apkofs.DirFS(t.Context(), tmpDir)

	// Call function under test
	licenseFiles, err = FindLicenseFiles(tmpFS, true)
	if len(licenseFiles) > 0 {
		t.Fatalf("Failed to test ignored files")
	}
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
	}
}

func TestCollectLicenseInfo(t *testing.T) {
	expectedLicenses := map[string]string{
		"LICENSE-APACHE":       "Apache-2.0",
		"LICENSE-BSD":          "BSD-3-Clause",
		"LICENSE-BSD-modified": "BSD-3-Clause",
		"LICENSE-GPLv2":        "GPL-2.0",
		"LICENSE-GPLv3":        "GPL-3.0",
		"COPYRIGHT":            "NOASSERTION",
		"ATYPICAL-FILENAME":    "Apache-2.0",
	}

	// ATYPICAL-FILENAME is not named like a license file, so it is reached
	// through a declaration rather than through discovery.
	cfg := &config.Configuration{
		Package: config.Package{
			Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: "ATYPICAL-FILENAME"},
			},
		},
	}

	dataFS := apkofs.DirFS(t.Context(), "testdata")

	licenses, err := CollectLicenseInfo(t.Context(), dataFS, true, cfg)
	if err != nil {
		t.Fatalf("CollectLicenseInfo returned an error: %v", err)
	}

	// These licenses are mostly-100% matched, so one result per file is expected.
	got := map[string][]string{}
	for _, l := range licenses {
		got[l.Source] = append(got[l.Source], l.Name)
	}

	for file, want := range expectedLicenses {
		names, ok := got[file]
		if !ok {
			t.Errorf("no license detected for file %s", file)
			continue
		}
		if len(names) != 1 {
			t.Errorf("expected one license detected for file %s, got %d: %v", file, len(names), names)
			continue
		}
		if names[0] != want {
			t.Errorf("expected license %s for file %s, got %s", want, file, names[0])
		}
	}
}

func TestLicenseCheck(t *testing.T) {
	// Create a mock configuration
	cfg := &config.Configuration{
		Package: config.Package{
			Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: "LICENSE-APACHE"},
				{License: "MIT", LicensePath: "LICENSE-BSD"},
				{License: "Apache-2.0", LicensePath: "ATYPICAL-FILENAME"},
				{License: "GPL-2.0 OR GPL-3.0"},
			},
		},
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(t.Context(), testDataDir)

	// Create a buffer to capture log output
	var logBuf strings.Builder
	handler := slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := clog.New(handler)
	ctx := clog.WithLogger(context.Background(), logger)

	// Call function under test
	_, diffs, err := LicenseCheck(ctx, cfg, dataFS, true)
	if err != nil {
		t.Fatalf("LicenseCheck returned an error: %v", err)
	}

	// Expected differences
	expectedDiffs := []LicenseDiff{
		{
			Path:   "LICENSE-BSD",
			Is:     "MIT",
			Should: "BSD-3-Clause",
		},
	}

	// Verify the results
	if len(diffs) != len(expectedDiffs) {
		t.Errorf("Expected %d license differences, got %d", len(expectedDiffs), len(diffs))
	}

	for _, expected := range expectedDiffs {
		found := false
		for _, diff := range diffs {
			if diff.Path == expected.Path && diff.Is == expected.Is && diff.Should == expected.Should {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license difference %+v not found", expected)
		}
	}

	// Now also check the log output and make sure that "low-confidence" is present only for the low-confidence
	// licenses: LICENSE-BSD-modified and COPYRIGHT (the latter is not a valid license)
	found := false
	lines := strings.SplitSeq(logBuf.String(), "\n")
	for line := range lines {
		if strings.Contains(line, "low-confidence") {
			// Check if the line contains one of the expected licenses
			if !strings.Contains(line, "LICENSE-BSD-modified") && !strings.Contains(line, "COPYRIGHT") {
				t.Errorf("Unexpected log line with 'low-confidence': %s", line)
			}
			found = true
		}
	}
	if !found {
		t.Error("Expected log line with 'low-confidence' not found")
	}
}

func TestFindLicenseFiles_shallow(t *testing.T) {
	// Create a temporary directory for testing with nested structure
	tmpDir := t.TempDir()

	testFiles := []struct {
		path          string
		shouldBeFound bool
	}{
		{"LICENSE", true},                      // top level
		{"subdir/LICENSE", true},               // one level down
		{"subdir/nested/LICENSE", false},       // two levels down (should be skipped in shallow)
		{"vendor/LICENSE", false},              // vendor directory (should be skipped)
		{"subdir/vendor/LICENSE", false},       // vendor in subdir (should be skipped)
		{"another/LICENSE", true},              // one level down in different dir
		{"another/deep/nested/LICENSE", false}, // deep nested (should be skipped)
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(tmpDir, tf.path)
		err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm)
		if err != nil {
			t.Fatalf("Failed to create directory for %s: %v", tf.path, err)
		}
		fp, err := os.OpenFile(filePath, os.O_RDONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", tf.path, err)
		}
		fp.Close()
	}

	tmpFS := apkofs.DirFS(t.Context(), tmpDir)

	// Test shallow scan (deep=false)
	licenseFiles, err := FindLicenseFiles(tmpFS, false)
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
	}

	t.Logf("Shallow scan found %d files", len(licenseFiles))
	for _, lf := range licenseFiles {
		t.Logf("  Found: %s", lf.Path)
	}

	// Verify we found the expected files
	expectedFiles := []string{"LICENSE", "subdir/LICENSE", "another/LICENSE"}
	if len(licenseFiles) != len(expectedFiles) {
		t.Errorf("Expected %d license files in shallow scan, got %d", len(expectedFiles), len(licenseFiles))
	}

	for _, expected := range expectedFiles {
		found := false
		for _, lf := range licenseFiles {
			if lf.Path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license file %s not found in shallow scan", expected)
		}
	}

	// Test deep scan (deep=true)
	licenseFilesDeep, err := FindLicenseFiles(tmpFS, true)
	if err != nil {
		t.Fatalf("FindLicenseFiles returned an error: %v", err)
	}

	t.Logf("Deep scan found %d files", len(licenseFilesDeep))
	for _, lf := range licenseFilesDeep {
		t.Logf("  Found: %s", lf.Path)
	}

	// Deep scan should find all files
	expectedDeepFiles := []string{
		"LICENSE",
		"subdir/LICENSE",
		"subdir/nested/LICENSE",
		"another/LICENSE",
		"another/deep/nested/LICENSE",
		"vendor/LICENSE",
		"subdir/vendor/LICENSE",
	}
	if len(licenseFilesDeep) != len(expectedDeepFiles) {
		t.Errorf("Expected %d license files in deep scan, got %d", len(expectedDeepFiles), len(licenseFilesDeep))
	}

	for _, expected := range expectedDeepFiles {
		found := false
		for _, lf := range licenseFilesDeep {
			if lf.Path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license file %s not found in deep scan", expected)
		}
	}

	// Verify vendor files ARE found in deep scan (only skipped in shallow)
	vendorFilesFound := 0
	for _, lf := range licenseFilesDeep {
		if strings.Contains(lf.Path, "vendor") {
			vendorFilesFound++
		}
	}
	if vendorFilesFound != 2 {
		t.Errorf("Expected 2 vendor files in deep scan, got %d", vendorFilesFound)
	}
}

func TestLicenseCheck_withOverrides(t *testing.T) {
	// Create a mock configuration with detection overrides
	// There is one correct override (BSD -> MIT) and one incorrect, where we say we expected MIT and overriding it to GPL-3.0
	cfg := &config.Configuration{
		Package: config.Package{
			Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: "LICENSE-APACHE"},
				{License: "MIT", LicensePath: "LICENSE-BSD", DetectionOverride: "BSD-3-Clause"},
				{License: "GPL-3.0", LicensePath: "LICENSE-GPLv2", DetectionOverride: "MIT"},
				{License: "GPL-3.0", LicensePath: "LICENSE-GPLv3"},
			},
		},
	}

	testDataDir := "testdata"
	dataFS := apkofs.DirFS(t.Context(), testDataDir)

	// Call function under test
	_, diffs, err := LicenseCheck(context.Background(), cfg, dataFS, true)
	if err != nil {
		t.Fatalf("LicenseCheck returned an error: %v", err)
	}

	// Expected differences
	expectedDiffs := []LicenseDiff{
		{
			Path:     "LICENSE-GPLv2",
			Is:       "GPL-3.0",
			Should:   "GPL-2.0",
			Override: "MIT",
		},
	}

	// Verify the results
	if len(diffs) != len(expectedDiffs) {
		t.Errorf("Expected %d license differences, got %d", len(expectedDiffs), len(diffs))
	}

	for _, expected := range expectedDiffs {
		found := false
		for _, diff := range diffs {
			if diff.Path == expected.Path && diff.Is == expected.Is && diff.Should == expected.Should && diff.Override == expected.Override {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected license difference %+v not found", expected)
		}
	}
}

func TestFindLicenseFiles_scope(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "LICENSE")
	if err := os.WriteFile(outside, nil, 0o644); err != nil {
		t.Fatalf("writing %s: %v", outside, err)
	}

	tests := []struct {
		path        string
		linkTo      string
		wantShallow bool
		wantDeep    bool
	}{
		{path: "LICENSE", wantShallow: true, wantDeep: true},
		{path: "PATENTS", wantShallow: true, wantDeep: true},
		{path: "tests/LICENSE", wantShallow: true, wantDeep: true},
		// A link is followed while it stays inside the tree, and skipped once
		// it leaves it.
		{path: "COPYING", linkTo: "LICENSE", wantShallow: true, wantDeep: true},
		{path: "LICENSE.outside", linkTo: outside},
		// Vendored source counts in a deep scan; a shallow scan does not enter it.
		{path: "vendor/github.com/x/y/LICENSE", wantDeep: true},
		{path: "third_party/LICENSE", wantDeep: true},
		{path: "third_party/protobuf/LICENSE", wantDeep: true},
		{path: "deps/zlib/LICENSE", wantDeep: true},
		{path: "external/COPYING", wantDeep: true},
		// What a build installed or produced never counts.
		{path: "node_modules/a/LICENSE"},
		{path: "venv/LICENSE"},
		{path: "rust-1.86.0-src/LICENSE-MIT"},
		{path: "melange-out/pkg/LICENSE"},
	}

	dir := t.TempDir()
	var wantShallow, wantDeep []string
	for _, tc := range tests {
		p := filepath.Join(dir, tc.path)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("creating the directory for %s: %v", tc.path, err)
		}
		var err error
		if tc.linkTo != "" {
			err = os.Symlink(tc.linkTo, p)
		} else {
			err = os.WriteFile(p, nil, 0o644)
		}
		if err != nil {
			t.Fatalf("creating %s: %v", tc.path, err)
		}
		if tc.wantShallow {
			wantShallow = append(wantShallow, tc.path)
		}
		if tc.wantDeep {
			wantDeep = append(wantDeep, tc.path)
		}
	}
	slices.Sort(wantShallow)
	slices.Sort(wantDeep)

	fsys := apkofs.DirFS(t.Context(), dir)
	for _, scan := range []struct {
		name string
		deep bool
		want []string
	}{
		{name: "shallow", want: wantShallow},
		{name: "deep", deep: true, want: wantDeep},
	} {
		t.Run(scan.name, func(t *testing.T) {
			files, err := FindLicenseFiles(fsys, scan.deep)
			if err != nil {
				t.Fatalf("FindLicenseFiles: %v", err)
			}
			got := make([]string, 0, len(files))
			for _, f := range files {
				got = append(got, f.Path)
			}
			slices.Sort(got)
			if diff := cmp.Diff(scan.want, got); diff != "" {
				t.Errorf("FindLicenseFiles (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestIsLicenseFile(t *testing.T) {
	// Paths are written as the QEMU runner's find(1) prints them.
	tests := []struct {
		path         string
		want         bool
		wantOverride bool
	}{
		{path: "./LICENSE", want: true, wantOverride: true},
		{path: "./PATENTS", want: true, wantOverride: true},
		{path: "./tests/LICENSE", want: true, wantOverride: true},
		{path: "./vendor/github.com/x/y/LICENSE", want: true, wantOverride: true},
		{path: "./third_party/zlib/COPYING", want: true, wantOverride: true},
		{path: "./node_modules/a/LICENSE", wantOverride: true},
		{path: "./venv/lib/LICENSE", wantOverride: true},
		{path: "./rust-1.86.0-src/LICENSE-MIT", wantOverride: true},
		{path: "./README.md"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			if got, _ := IsLicenseFile(tc.path, false); got != tc.want {
				t.Errorf("IsLicenseFile(%q, false): got = %v, want = %v", tc.path, got, tc.want)
			}
			if got, _ := IsLicenseFile(tc.path, true); got != tc.wantOverride {
				t.Errorf("IsLicenseFile(%q, true): got = %v, want = %v", tc.path, got, tc.wantOverride)
			}
		})
	}
}

func TestCollectLicenseInfo_declaredUnderInstalledTree(t *testing.T) {
	bsd, err := os.ReadFile(filepath.Join("testdata", "LICENSE-BSD"))
	if err != nil {
		t.Fatalf("reading the BSD fixture: %v", err)
	}
	const declared = "node_modules/bundled/COPYING"
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(declared)), 0o755); err != nil {
		t.Fatalf("creating the directory for %s: %v", declared, err)
	}
	if err := os.WriteFile(filepath.Join(dir, declared), bsd, 0o644); err != nil {
		t.Fatalf("writing %s: %v", declared, err)
	}
	fsys := apkofs.DirFS(t.Context(), dir)

	for _, licensePath := range []string{declared, "./" + declared} {
		for _, deep := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deep=%v", licensePath, deep), func(t *testing.T) {
				cfg := &config.Configuration{Package: config.Package{Copyright: []config.Copyright{
					{License: "BSD-3-Clause", LicensePath: licensePath},
				}}}
				licenses, err := CollectLicenseInfo(t.Context(), fsys, deep, cfg)
				if err != nil {
					t.Fatalf("CollectLicenseInfo: %v", err)
				}
				var got []string
				for _, l := range licenses {
					if l.Source == path.Clean(licensePath) {
						got = append(got, l.Name)
					}
				}
				if diff := cmp.Diff([]string{"BSD-3-Clause"}, got); diff != "" {
					t.Errorf("licenses detected in %s (-want, +got):\n%s", declared, diff)
				}
			})
		}
	}
}

// lockedDirFS returns a tree whose locked/ directory cannot be listed, and skips
// the test where permissions are not enforced, as they are not for root.
func lockedDirFS(t *testing.T) fs.FS {
	t.Helper()
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("creating %s: %v", locked, err)
	}
	if err := os.WriteFile(filepath.Join(locked, "LICENSE"), nil, 0o644); err != nil {
		t.Fatalf("writing into %s: %v", locked, err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("locking %s: %v", locked, err)
	}
	// Registered after t.TempDir, so it runs first: the directory cannot be
	// removed while it stays locked.
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if _, err := os.ReadDir(locked); err == nil {
		t.Skip("directory permissions are not enforced for this user")
	}
	return apkofs.DirFS(t.Context(), dir)
}

func TestFindLicenseFiles_unreadable(t *testing.T) {
	for _, deep := range []bool{false, true} {
		t.Run(fmt.Sprintf("deep=%v", deep), func(t *testing.T) {
			_, err := FindLicenseFiles(lockedDirFS(t), deep)
			if err == nil || !strings.Contains(err.Error(), "locked") {
				t.Errorf("FindLicenseFiles: got error %v, want one naming locked", err)
			}
		})
	}
}

func TestCollectLicenseInfo_unreadable(t *testing.T) {
	tests := []struct {
		name    string
		fsys    func(t *testing.T) fs.FS
		cfg     *config.Configuration
		wantErr string
	}{
		{
			name: "declared license-path missing",
			fsys: func(t *testing.T) fs.FS { return apkofs.DirFS(t.Context(), "testdata") },
			cfg: &config.Configuration{Package: config.Package{Copyright: []config.Copyright{
				{License: "MIT", LicensePath: "does-not-exist"},
			}}},
			wantErr: "does-not-exist",
		},
		{
			name:    "directory unreadable",
			fsys:    lockedDirFS,
			wantErr: "locked",
		},
	}
	for _, tc := range tests {
		for _, deep := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deep=%v", tc.name, deep), func(t *testing.T) {
				_, err := CollectLicenseInfo(t.Context(), tc.fsys(t), deep, tc.cfg)
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("CollectLicenseInfo: got error %v, want one naming %s", err, tc.wantErr)
				}
			})
		}
	}
}

func TestCollectLicenseInfo_warnsPastClassifiedBytes(t *testing.T) {
	apache, err := os.ReadFile(filepath.Join("testdata", "LICENSE-APACHE"))
	if err != nil {
		t.Fatalf("reading the Apache fixture: %v", err)
	}
	tests := []struct {
		name     string
		content  []byte
		wantWarn bool
	}{
		{name: "within the bound", content: apache},
		{
			name:     "past the bound",
			content:  append(slices.Clone(apache), bytes.Repeat([]byte("x"), detect.MaxTextBytes)...),
			wantWarn: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "LICENSE"), tc.content, 0o644); err != nil {
				t.Fatalf("writing LICENSE: %v", err)
			}
			var logBuf strings.Builder
			ctx := clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))

			if _, err := CollectLicenseInfo(ctx, apkofs.DirFS(ctx, dir), false, nil); err != nil {
				t.Fatalf("CollectLicenseInfo: %v", err)
			}
			if got := strings.Contains(logBuf.String(), "are classified"); got != tc.wantWarn {
				t.Errorf("warned that only part of LICENSE is classified: got = %v, want = %v\nlog:\n%s", got, tc.wantWarn, logBuf.String())
			}
		})
	}
}

func TestLicenseCheck_declaredPathForms(t *testing.T) {
	// ATYPICAL-FILENAME is reached only through its declaration; LICENSE-APACHE
	// is also found by name.
	for _, licensePath := range []string{"ATYPICAL-FILENAME", "./ATYPICAL-FILENAME", "LICENSE-APACHE", "./LICENSE-APACHE"} {
		t.Run(licensePath, func(t *testing.T) {
			cfg := &config.Configuration{Package: config.Package{Copyright: []config.Copyright{
				{License: "Apache-2.0", LicensePath: licensePath},
			}}}
			_, diffs, err := LicenseCheck(t.Context(), cfg, apkofs.DirFS(t.Context(), "testdata"), false)
			if err != nil {
				t.Fatalf("LicenseCheck: %v", err)
			}
			for _, d := range diffs {
				if d.Path == path.Clean(licensePath) {
					t.Errorf("declared %s as Apache-2.0, got difference %+v", licensePath, d)
				}
			}
		})
	}
}
