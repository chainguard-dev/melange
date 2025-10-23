// Copyright 2023 Chainguard, Inc.
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

package linter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"
	"github.com/dustin/go-humanize"
	"golang.org/x/exp/maps"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"

	"chainguard.dev/apko/pkg/apk/auth"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/linter/types"
)

type linterFunc func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error

type linter struct {
	LinterFunc      linterFunc
	Explain         string
	defaultBehavior defaultBehavior
}

type defaultBehavior int

const (
	// Ignore the linter (default)
	Ignore defaultBehavior = iota
	// Require the linter.
	Require
	// Warn about the linter.
	Warn
)

// collectMatchingPaths walks the filesystem and collects all paths matching the predicate,
// returning a structured error if any paths are found.
func collectMatchingPaths(ctx context.Context, pkgname string, fsys fs.FS, predicate func(path string) bool, messageFunc func(pkgname string, paths []string) string) error {
	var matchedPaths []string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if predicate(path) {
			matchedPaths = append(matchedPaths, path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	if len(matchedPaths) > 0 {
		details := &types.PathListDetails{
			Paths: matchedPaths,
		}
		return types.NewStructuredError(messageFunc(pkgname, matchedPaths), details)
	}

	return nil
}

func DefaultRequiredLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Require })
	slices.Sort(l)
	return l
}

func DefaultWarnLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Warn })
	slices.Sort(l)
	return l
}

var linterMap = map[string]linter{
	"dev": {
		LinterFunc:      devLinter,
		Explain:         "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
		defaultBehavior: Require,
	},
	"documentation": {
		LinterFunc:      documentationLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Ignore, // TODO: Lots of packages write to READMEs, etc.
	},
	"opt": {
		LinterFunc:      optLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"object": {
		LinterFunc:      objectLinter,
		Explain:         "This package contains intermediate object files (.o files)",
		defaultBehavior: Warn,
	},
	"maninfo": {
		LinterFunc:      manInfoLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Warn,
	},
	"sbom": {
		LinterFunc:      sbomLinter,
		Explain:         "Remove any files in /var/lib/db/sbom from the package",
		defaultBehavior: Warn, // TODO: needs work to be useful
	},
	"setuidgid": {
		LinterFunc:      isSetUIDOrGIDLinter,
		Explain:         "Unset the setuid/setgid bit on the relevant files, or remove this linter",
		defaultBehavior: Require,
	},
	"srv": {
		LinterFunc:      srvLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"tempdir": {
		LinterFunc:      tempDirLinter,
		Explain:         "Remove any offending files in temporary dirs in the pipeline",
		defaultBehavior: Require,
	},
	"usrlocal": {
		LinterFunc:      usrLocalLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"varempty": {
		LinterFunc:      varEmptyLinter,
		Explain:         "Remove any offending files in /var/empty in the pipeline",
		defaultBehavior: Require,
	},
	"worldwrite": {
		LinterFunc:      worldWriteableLinter,
		Explain:         "Change the permissions of any permissive files in the package, disable the linter, or make this a -compat package",
		defaultBehavior: Require,
	},
	"strip": {
		LinterFunc:      strippedLinter,
		Explain:         "Properly strip all binaries in the pipeline",
		defaultBehavior: Warn,
	},
	"infodir": {
		LinterFunc:      infodirLinter,
		Explain:         "Remove /usr/share/info/dir from the package (run split/infodir)",
		defaultBehavior: Require,
	},
	"empty": {
		LinterFunc:      emptyLinter,
		Explain:         "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
		defaultBehavior: Ignore, // TODO: Needs to ignore packages that specify no-provides.
	},
	"python/docs": {
		LinterFunc:      pythonDocsLinter,
		Explain:         "Remove all docs directories from the package",
		defaultBehavior: Warn,
	},
	"python/multiple": {
		LinterFunc:      pythonMultiplePackagesLinter,
		Explain:         "Split this package up into multiple packages and verify you are not improperly using pip install",
		defaultBehavior: Warn,
	},
	"python/test": {
		LinterFunc:      pythonTestLinter,
		Explain:         "Remove all test directories from the package",
		defaultBehavior: Warn,
	},
	"pkgconf": {
		LinterFunc:      pkgconfTestLinter,
		Explain:         "This package provides files in a pkgconfig directory, please add the pkgconf test pipeline",
		defaultBehavior: Warn,
	},
	"lddcheck": {
		LinterFunc:      lddcheckTestLinter,
		Explain:         "This package provides shared object files, please add the ldd-check test pipeline",
		defaultBehavior: Warn,
	},
	"usrmerge": {
		LinterFunc:      usrmergeLinter,
		Explain:         "Move binary to /usr/bin",
		defaultBehavior: Require,
	},
	"cudaruntimelib": {
		LinterFunc:      cudaDriverLibLinter,
		Explain:         "CUDA driver-specific libraries should be passed into the container by the host. Installing them in an image could override the host libraries and break GPU support. If this library is needed for build-time linking or ldd-check tests, please use a package containing a stub library instead. For libcuda.so, use nvidia-cuda-cudart-$cuda_version. For libnvidia-ml.so, use nvidia-cuda-nvml-dev-$cuda_version.",
		defaultBehavior: Warn,
	},
	"dll": {
		LinterFunc:      dllLinter,
		Explain:         "This package contains Windows libraries",
		defaultBehavior: Warn,
	},
	"dylib": {
		LinterFunc:      dylibLinter,
		Explain:         "This package contains macOS libraries",
		defaultBehavior: Warn,
	},
	"nonlinux": {
		LinterFunc:      nonLinuxLinter,
		Explain:         "This package contains references to non-Linux paths",
		defaultBehavior: Warn,
	},
	"unsupportedarch": {
		LinterFunc:      unsupportedArchLinter,
		Explain:         "This package contains references to unsupported architectures (only aarch64/arm64 and amd64/x86_64 are supported)",
		defaultBehavior: Warn,
	},
	"binaryarch": {
		LinterFunc:      binaryArchLinter,
		Explain:         "This package contains binaries compiled for unsupported architectures (only aarch64/arm64 and amd64/x86_64 binaries are supported)",
		defaultBehavior: Warn,
	},
	"staticarchive": {
		LinterFunc:      staticArchiveLinter,
		Explain:         "This package contains static archives (.a files)",
		defaultBehavior: Warn,
	},
	"duplicate": {
		LinterFunc:      duplicateLinter,
		Explain:         "This package contains files with the same name and content in different directories (consider symlinking)",
		defaultBehavior: Warn,
	},
}

// Determine if a path should be ignored by a linter
func isIgnoredPath(path string) bool {
	return strings.HasPrefix(path, "var/lib/db/sbom/")
}

func devLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "dev/") },
		func(pkgname string, paths []string) string { return fmt.Sprintf("%s writes to /dev", pkgname) },
	)
}

func optLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-compat") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "opt/") },
		func(pkgname string, paths []string) string { return fmt.Sprintf("%s writes to /opt", pkgname) },
	)
}

func objectLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return filepath.Ext(path) == ".o" },
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d intermediate object %s. This is usually wrong. In most cases they should be removed", pkgname, len(paths), fileWord)
		},
	)
}

func staticArchiveLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	// Static archives are expected in -dev/-static packages
	if strings.HasSuffix(pkgname, "-dev") || strings.HasSuffix(pkgname, "-static") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return filepath.Ext(path) == ".a" },
		func(pkgname string, paths []string) string {
			fileWord := "archive"
			if len(paths) > 1 {
				fileWord = "archives"
			}
			return fmt.Sprintf("%s contains %d static %s. Static archives bloat packages and should typically be in -dev packages or removed", pkgname, len(paths), fileWord)
		},
	)
}

func dllLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-dev") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return filepath.Ext(path) == ".dll" },
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d DLL %s", pkgname, len(paths), fileWord)
		},
	)
}

func dylibLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-dev") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return filepath.Ext(path) == ".dylib" },
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d dylib %s", pkgname, len(paths), fileWord)
		},
	)
}

func nonLinuxLinter(_ context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	// Map of canonical platform name -> variants to detect in paths
	platforms := map[string][]string{
		"macos":   {"darwin", "macos", "mac_os", "mac-os", "osx", "os_x", "os-x"},
		"windows": {"windows", "win32", "win64"},
	}

	var references []types.NonLinuxReference

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		dirLower := strings.ToLower(filepath.Dir(path))
		baseLower := strings.ToLower(filepath.Base(path))

		// Check for platform references in the path
		for platform, variants := range platforms {
			for _, variant := range variants {
				if strings.Contains(dirLower, variant) || strings.Contains(baseLower, variant) {
					references = append(references, types.NonLinuxReference{
						Path:     path,
						Platform: platform,
					})
					return nil // Found a match for this file, move to next file
				}
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(references) > 0 {
		details := &types.NonLinuxDetails{
			References: references,
		}

		message := fmt.Sprintf("%s contains %d non-Linux reference(s)", pkgname, len(references))
		return types.NewStructuredError(message, details)
	}

	return nil
}

func unsupportedArchLinter(_ context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	supported := []string{"aarch64", "arm64", "amd64", "x86_64", "x86-64"}

	archs := []string{
		"i386", "i686", "x86_32", "x86-32",
		"ppc64", "ppc64le", "powerpc",
		"s390x", "s390",
		"mips", "mipsel", "mips64",
		"riscv", "riscv64",
		"sparc", "sparc64",
		"ia64", "m68k",
	}

	var unsupportedFiles []types.UnsupportedArchInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		pathLower := strings.ToLower(path)
		dirLower := strings.ToLower(filepath.Dir(path))
		baseLower := strings.ToLower(filepath.Base(path))

		for _, arch := range archs {
			if strings.Contains(dirLower, "/"+arch+"/") || strings.Contains(dirLower, "/"+arch) && dirLower == strings.ToLower(filepath.Dir(path)) {
				unsupportedFiles = append(unsupportedFiles, types.UnsupportedArchInfo{
					Path: path,
					Arch: arch,
				})
				return nil
			}

			for _, sep := range []string{"-", "_", "."} {
				if strings.Contains(baseLower, sep+arch+sep) ||
					strings.Contains(baseLower, sep+arch+".") ||
					strings.HasSuffix(baseLower, sep+arch) {

					isSupported := false
					for _, s := range supported {
						if strings.Contains(pathLower, s) {
							isSupported = true
							break
						}
					}
					if !isSupported {
						unsupportedFiles = append(unsupportedFiles, types.UnsupportedArchInfo{
							Path: path,
							Arch: arch,
						})
						return nil
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(unsupportedFiles) > 0 {
		details := &types.UnsupportedArchDetails{
			Files: unsupportedFiles,
		}

		message := fmt.Sprintf("%s contains %d unsupported architecture reference(s)", pkgname, len(unsupportedFiles))
		return types.NewStructuredError(message, details)
	}

	return nil
}

func binaryArchLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var unsupportedBinaries []types.BinaryArchInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if isIgnoredPath(path) {
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() < int64(len(elfMagic)) {
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !isObjectFileRegex.MatchString(ext) {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return nil
		}

		hdr := make([]byte, len(elfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return nil
		}

		if !bytes.Equal(elfMagic, hdr) {
			return nil
		}

		elfFile, err := elf.NewFile(readerAt)
		if err != nil {
			return nil
		}
		defer elfFile.Close()

		var archName string
		switch elfFile.Machine {
		case elf.EM_X86_64:
			archName = "amd64"
		case elf.EM_AARCH64:
			archName = "arm64"
		case elf.EM_386:
			archName = "i386"
		case elf.EM_ARM:
			archName = "arm"
		case elf.EM_PPC64:
			archName = "ppc64"
		case elf.EM_S390:
			archName = "s390"
		case elf.EM_MIPS:
			archName = "mips"
		case elf.EM_RISCV:
			archName = "riscv"
		default:
			archName = fmt.Sprintf("unknown (%v)", elfFile.Machine)
		}

		if elfFile.Machine != elf.EM_X86_64 && elfFile.Machine != elf.EM_AARCH64 {
			unsupportedBinaries = append(unsupportedBinaries, types.BinaryArchInfo{
				Path: path,
				Arch: archName,
			})
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(unsupportedBinaries) > 0 {
		details := &types.BinaryArchDetails{
			Binaries: unsupportedBinaries,
		}

		binaryWord := "binary"
		if len(unsupportedBinaries) > 1 {
			binaryWord = "binaries"
		}
		message := fmt.Sprintf("%s contains %d %s compiled for unsupported architecture(s)", pkgname, len(unsupportedBinaries), binaryWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}

type duplicateInfo struct {
	paths []string
	size  int64
}

func duplicateLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	type fileKey struct {
		hash     string
		basename string
	}
	filesByKey := make(map[fileKey]*duplicateInfo)

	const minFileSizeBytes = 1024 // 1 KB

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		basename := filepath.Base(path)

		if isLicense, _ := license.IsLicenseFile(path, true); isLicense {
			return nil
		}

		if info.Size() < minFileSizeBytes {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %s: %w", path, err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return fmt.Errorf("hashing file %s: %w", path, err)
		}

		hash := hex.EncodeToString(h.Sum(nil))
		key := fileKey{hash: hash, basename: basename}

		if existing, found := filesByKey[key]; found {
			existing.paths = append(existing.paths, path)
		} else {
			filesByKey[key] = &duplicateInfo{
				paths: []string{path},
				size:  info.Size(),
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	type duplicateSet struct {
		count    int
		size     int64
		wasted   int64
		paths    []string
		basename string
	}

	var duplicateSets []duplicateSet
	var totalWasted int64

	for key, info := range filesByKey {
		if len(info.paths) > 1 {
			slices.Sort(info.paths)

			wasted := int64(len(info.paths)-1) * info.size
			totalWasted += wasted

			duplicateSets = append(duplicateSets, duplicateSet{
				count:    len(info.paths),
				size:     info.size,
				wasted:   wasted,
				paths:    info.paths,
				basename: key.basename,
			})
		}
	}

	if len(duplicateSets) > 0 {
		slices.SortFunc(duplicateSets, func(a, b duplicateSet) int {
			if a.wasted > b.wasted {
				return -1
			} else if a.wasted < b.wasted {
				return 1
			}
			return 0
		})

		// Build structured details
		duplicates := make([]*types.DuplicateFileInfo, 0, len(duplicateSets))
		for _, ds := range duplicateSets {
			duplicates = append(duplicates, &types.DuplicateFileInfo{
				Basename:    ds.basename,
				Count:       ds.count,
				SizeBytes:   ds.size,
				Size:        humanize.Bytes(uint64(ds.size)),
				WastedBytes: ds.wasted,
				WastedSize:  humanize.Bytes(uint64(ds.wasted)),
				Paths:       ds.paths,
			})
		}

		details := &types.DuplicateFilesDetails{
			TotalDuplicateSets: len(duplicateSets),
			TotalWastedBytes:   totalWasted,
			TotalWastedSize:    humanize.Bytes(uint64(totalWasted)),
			Duplicates:         duplicates,
		}

		// Build human-readable message for logs
		var output []string
		for _, ds := range duplicateSets {
			output = append(output, fmt.Sprintf(
				"  %d copies of '%s' (%s each, wasting %s):",
				ds.count,
				ds.basename,
				humanize.Bytes(uint64(ds.size)),
				humanize.Bytes(uint64(ds.wasted)),
			))

			for _, p := range ds.paths {
				output = append(output, "    "+p)
			}
		}

		summary := fmt.Sprintf("%s contains %d duplicate file(s) with same name in different directories (wasting %s total)", pkgname, len(duplicateSets), humanize.Bytes(uint64(totalWasted)))
		message := fmt.Sprintf("%s:\n%s", summary, strings.Join(output, "\n"))

		return types.NewStructuredError(message, details)
	}

	return nil
}

var isDocumentationFileRegex = regexp.MustCompile(`(?:READ(?:\.?ME)?|TODO|CREDITS|\.(?:md|docx?|rst|[0-9][a-z]))$`)

func documentationLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-doc") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return isDocumentationFileRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d documentation %s but is not a documentation package", pkgname, len(paths), fileWord)
		},
	)
}

var (
	manRegex  = regexp.MustCompile(`^usr/(?:local/)?share/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$|^usr/man(?:/man[0-9][^/]*)?(?:/[^/]+\.[0-9][^/]*(?:\.(?:gz|bz2|xz|lzma|Z))?)?$`)
	infoRegex = regexp.MustCompile(`^usr/(?:local/)?share/info/(?:dir|[^/]+\.info(?:\-[0-9]+)?(?:\.(?:gz|bz2|xz|lzma|Z))?)$`)
)

func manInfoLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-doc") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return manRegex.MatchString(path) || infoRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			fileWord := "file"
			if len(paths) > 1 {
				fileWord = "files"
			}
			return fmt.Sprintf("%s contains %d man/info %s but is not a documentation package", pkgname, len(paths), fileWord)
		},
	)
}

func modeToOctal(mode os.FileMode) string {
	perm := uint64(mode.Perm())

	if mode&os.ModeSetuid != 0 {
		perm |= 04000
	}
	if mode&os.ModeSetgid != 0 {
		perm |= 02000
	}
	if mode&os.ModeSticky != 0 {
		perm |= 01000
	}

	return strconv.FormatUint(perm, 8)
}

func isSetUIDOrGIDLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var specialPermFiles []types.FilePermissionInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		bits := mode & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		if bits != 0 {
			var parts []string
			if mode&fs.ModeSetuid != 0 {
				parts = append(parts, "setuid")
			}
			if mode&fs.ModeSetgid != 0 {
				parts = append(parts, "setgid")
			}
			if mode&fs.ModeSticky != 0 {
				parts = append(parts, "sticky")
			}
			specialPermFiles = append(specialPermFiles, types.FilePermissionInfo{
				Path:        path,
				Mode:        perm,
				Permissions: parts,
			})
		}

		return nil
	})

	if err != nil {
		return err
	}

	if len(specialPermFiles) > 0 {
		details := &types.SpecialPermissionsDetails{
			Files: specialPermFiles,
		}

		fileWord := "file"
		if len(specialPermFiles) > 1 {
			fileWord = "files"
		}
		message := fmt.Sprintf("%s contains %d %s with special permissions (setuid/setgid)", pkgname, len(specialPermFiles), fileWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}

func sbomLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool {
			return filepath.Dir(path) == "var/lib/db/sbom" && !strings.HasSuffix(path, ".spdx.json")
		},
		func(pkgname string, paths []string) string {
			return fmt.Sprintf("%s writes to var/lib/db/sbom", pkgname)
		},
	)
}

func infodirLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "usr/share/info/dir/") },
		func(pkgname string, paths []string) string {
			return fmt.Sprintf("%s writes to /usr/share/info/dir/", pkgname)
		},
	)
}

func srvLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-compat") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "srv/") },
		func(pkgname string, paths []string) string { return fmt.Sprintf("%s writes to /srv", pkgname) },
	)
}

var isTempDirRegex = regexp.MustCompile("^(var/)?(tmp|run)/")

func tempDirLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return isTempDirRegex.MatchString(path) },
		func(pkgname string, paths []string) string { return fmt.Sprintf("%s writes to a temp dir", pkgname) },
	)
}

func usrLocalLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	if strings.HasSuffix(pkgname, "-compat") {
		return nil
	}
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "usr/local/") },
		func(pkgname string, paths []string) string {
			return fmt.Sprintf("%s contains /usr/local path in non-compat package", pkgname)
		},
	)
}

func varEmptyLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return strings.HasPrefix(path, "var/empty/") },
		func(pkgname string, paths []string) string { return fmt.Sprintf("%s writes to /var/empty", pkgname) },
	)
}

func worldWriteableLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var worldWriteableFiles []types.FilePermissionInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if !d.Type().IsRegular() { // Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		mode := info.Mode()
		perm := modeToOctal(mode)

		if mode&0o002 != 0 {
			permissions := []string{"world-writable"}
			if mode&0o111 != 0 {
				permissions = append(permissions, "executable")
			}
			worldWriteableFiles = append(worldWriteableFiles, types.FilePermissionInfo{
				Path:        path,
				Mode:        perm,
				Permissions: permissions,
			})
		}
		return nil
	})

	if err != nil {
		return err
	}

	if len(worldWriteableFiles) > 0 {
		details := &types.WorldWriteableDetails{
			Files: worldWriteableFiles,
		}

		fileWord := "file"
		if len(worldWriteableFiles) > 1 {
			fileWord = "files"
		}
		message := fmt.Sprintf("%s contains %d world-writeable %s", pkgname, len(worldWriteableFiles), fileWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}

var elfMagic = []byte{'\x7f', 'E', 'L', 'F'}

var isObjectFileRegex = regexp.MustCompile(`\.(a|so|dylib)(\..*)?`)

func strippedLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var unstrippedBinaries []string

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if isIgnoredPath(path) {
			return nil
		}

		if !d.Type().IsRegular() {
			// Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() < int64(len(elfMagic)) {
			// This is definitely not an ELF file.
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !isObjectFileRegex.MatchString(ext) {
			// Not an executable or library
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer f.Close()

		// Both os.DirFS and go-apk return a file that implements ReaderAt.
		// We don't have any other callers, so this should never fail.
		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return fmt.Errorf("fs.File does not impl ReaderAt: %T", f)
		}

		hdr := make([]byte, len(elfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return fmt.Errorf("failed to read %d bytes for magic ELF header: %w", len(elfMagic), err)
		}

		if !bytes.Equal(elfMagic, hdr) {
			// No magic header, definitely not ELF.
			return nil
		}

		file, err := elf.NewFile(readerAt)
		if err != nil {
			return fmt.Errorf("Could not open file %q as executable: %v\n", path, err)
		}
		defer file.Close()

		// No debug sections allowed
		if file.Section(".debug") != nil || file.Section(".zdebug") != nil {
			unstrippedBinaries = append(unstrippedBinaries, path)
		}
		return nil
	})

	if err != nil {
		return err
	}

	if len(unstrippedBinaries) > 0 {
		details := &types.UnstrippedBinaryDetails{
			Binaries: unstrippedBinaries,
		}

		binaryWord := "binary"
		if len(unstrippedBinaries) > 1 {
			binaryWord = "binaries"
		}
		message := fmt.Sprintf("%s contains %d unstripped %s", pkgname, len(unstrippedBinaries), binaryWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}

func emptyLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	foundfile := false
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if isIgnoredPath(path) {
			return nil
		}

		if d.IsDir() {
			// Ignore directories
			return nil
		}

		foundfile = true
		return fs.SkipAll
	})
	if err != nil {
		return err
	}

	// Nothing to do
	if foundfile {
		return nil
	}

	return fmt.Errorf("package is empty but no-provides is not set")
}

func getPythonSitePackages(fsys fs.FS) (matches []string, err error) {
	pythondirs, err := fs.Glob(fsys, filepath.Join("usr", "lib", "python3.*"))
	if err != nil {
		// Shouldn't get here, per the Go docs.
		err = fmt.Errorf("error checking for Python site directories: %w", err)
		return
	}

	if len(pythondirs) == 0 {
		// Nothing to do
		return
	} else if len(pythondirs) > 1 {
		err = fmt.Errorf("more than one Python version detected: %d found", len(pythondirs))
		return
	}

	matches, err = fs.Glob(fsys, filepath.Join(pythondirs[0], "site-packages", "*"))
	if err != nil {
		// Shouldn't get here as well.
		err = fmt.Errorf("error checking for Python packages: %w", err)
		return
	}

	return
}

func pythonDocsLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	for _, m := range packages {
		base := filepath.Base(m)
		if base == "doc" || base == "docs" {
			return fmt.Errorf("docs directory encountered in Python site-packages directory")
		}
	}

	return nil
}

func pythonMultiplePackagesLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	// Filter matches and ignore duplicates (.so vs directories for example)
	pmatches := map[string]struct{}{}
	for _, m := range packages {
		base := filepath.Base(m)

		if strings.HasPrefix(base, "_") {
			// Ignore __pycache__ and internal packages
			continue
		}

		if base == "test" || base == "tests" {
			// Exclude tests
			continue
		}

		if base == "doc" || base == "docs" {
			// Exclude docs
			continue
		}

		ext := filepath.Ext(base)
		if ext == ".egg-info" || ext == ".dist-info" || ext == ".pth" {
			// Exclude various metadata files and .so files
			continue
		}

		if len(ext) > 0 {
			base = base[:len(ext)]
			if base == "" {
				// No empty strings
				continue
			}
		}
		pmatches[fmt.Sprintf("%q", base)] = struct{}{}
	}

	if len(pmatches) > 1 {
		i := 0
		slmatches := make([]string, len(pmatches))
		for k := range pmatches {
			slmatches[i] = k
			i++
		}
		slices.Sort(slmatches)

		details := &types.PythonMultipleDetails{
			Count:    len(slmatches),
			Packages: slmatches,
		}

		smatches := strings.Join(slmatches, ", ")
		message := fmt.Sprintf("multiple Python packages detected: %d found (%s)", len(slmatches), smatches)

		return types.NewStructuredError(message, details)
	}

	return nil
}

func pythonTestLinter(_ context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	packages, err := getPythonSitePackages(fsys)
	if err != nil {
		return err
	}

	for _, m := range packages {
		base := filepath.Base(m)
		if base == "test" || base == "tests" {
			return fmt.Errorf("tests directory encountered in Python site-packages directory")
		}
	}

	return nil
}

var PkgconfDirRegex = regexp.MustCompile("^usr/(lib|share)/pkgconfig/")

func pkgconfTestLinter(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	// Check if the appropriate test is configured
	hasTest := false
	if cfg != nil {
		if cfg.Package.Name == pkgname {
			if cfg.Test != nil {
				for _, test := range cfg.Test.Pipeline {
					if test.Uses == "test/pkgconf" {
						hasTest = true
						break
					}
				}
			}
		} else {
			for _, p := range cfg.Subpackages {
				if p.Name == pkgname {
					if p.Test != nil {
						for _, test := range p.Test.Pipeline {
							if test.Uses == "test/pkgconf" {
								hasTest = true
								break
							}
						}
					}
					break
				}
			}
		}
	}

	// If test is configured, no need to check files
	if hasTest {
		return nil
	}

	// Collect all pkgconfig files
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return PkgconfDirRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			if cfg == nil {
				return fmt.Sprintf("%s contains pkgconfig files but missing .melange.yaml", pkgname)
			}
			return fmt.Sprintf("%s contains pkgconfig files but test/pkgconf is not configured", pkgname)
		},
	)
}

var isSharedObjectFileRegex = regexp.MustCompile(`\.so(?:\.[0-9]+)*$`)

func lddcheckTestLinter(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error {
	// Check if the appropriate test is configured
	hasTest := false
	if cfg != nil {
		if cfg.Package.Name == pkgname {
			if cfg.Test != nil {
				for _, test := range cfg.Test.Pipeline {
					if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
						hasTest = true
						break
					}
				}
			}
		} else {
			for _, p := range cfg.Subpackages {
				if p.Name == pkgname {
					if p.Test != nil {
						for _, test := range p.Test.Pipeline {
							if test.Uses == "test/ldd-check" || test.Uses == "test/tw/ldd-check" {
								hasTest = true
								break
							}
						}
					}
					break
				}
			}
		}
	}

	// If test is configured, no need to check files
	if hasTest {
		return nil
	}

	// Collect all shared object files
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return isSharedObjectFileRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			if cfg == nil {
				return fmt.Sprintf("%s contains shared objects but missing .melange.yaml", pkgname)
			}
			return fmt.Sprintf("%s contains shared objects but test/ldd-check is not configured", pkgname)
		},
	)
}

// logStructuredDetails displays itemized details for structured errors
func logStructuredDetails(log *clog.Logger, details any) {
	if details == nil {
		return
	}

	switch d := details.(type) {
	case *types.DuplicateFilesDetails:
		for _, dup := range d.Duplicates {
			log.Warnf("    - %s (%d copies, %s wasted)", dup.Basename, dup.Count, dup.WastedSize)
		}
	case *types.NonLinuxDetails:
		for _, ref := range d.References {
			log.Warnf("    - %s (%s)", ref.Path, ref.Platform)
		}
	case *types.UnsupportedArchDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (%s)", file.Path, file.Arch)
		}
	case *types.BinaryArchDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s (%s)", bin.Path, bin.Arch)
		}
	case *types.SpecialPermissionsDetails:
		for _, file := range d.Files {
			log.Warnf("    - %s (mode: %s, %s)", file.Path, file.Mode, strings.Join(file.Permissions, "+"))
		}
	case *types.WorldWriteableDetails:
		for _, file := range d.Files {
			perms := ""
			if len(file.Permissions) > 0 {
				perms = fmt.Sprintf(" [%s]", strings.Join(file.Permissions, "+"))
			}
			log.Warnf("    - %s (mode: %s)%s", file.Path, file.Mode, perms)
		}
	case *types.UnstrippedBinaryDetails:
		for _, bin := range d.Binaries {
			log.Warnf("    - %s", bin)
		}
	case *types.PythonMultipleDetails:
		for _, pkg := range d.Packages {
			log.Warnf("    - %s", pkg)
		}
	case *types.PathListDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	case *types.UsrMergeDetails:
		for _, path := range d.Paths {
			log.Warnf("    - %s", path)
		}
	}
}

func lintPackageFS(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS, linters []string, results map[string]*types.PackageLintResults, fullPackageName string) error {
	log := clog.FromContext(ctx)
	var errs []error

	for _, linterName := range linters {
		if err := ctx.Err(); err != nil {
			return err
		}
		linter := linterMap[linterName]
		if err := linter.LinterFunc(ctx, cfg, pkgname, fsys); err != nil {
			// Extract message and structured details if available
			var message string
			var details any

			if structErr, ok := err.(*types.StructuredError); ok {
				message = structErr.Message
				details = structErr.Details
			} else {
				message = err.Error()
			}

			// Split message into lines for better console readability
			messageLines := strings.Split(message, "\n")

			// Log multi-line errors with proper formatting
			log.Warnf("[%s] %s", linterName, messageLines[0])
			for _, line := range messageLines[1:] {
				if line != "" {
					log.Warnf("  %s", line)
				}
			}

			// Initialize package results
			if _, ok := results[pkgname]; !ok {
				results[pkgname] = &types.PackageLintResults{
					PackageName: fullPackageName,
					Findings:    make(map[string][]*types.LinterFinding),
				}
			}

			// Append finding to the linter's findings list
			finding := &types.LinterFinding{
				Message: messageLines[0], // Use first line as the summary message
				Details: details,
			}
			if linter.Explain != "" {
				log.Warnf("  → %s", linter.Explain)
				finding.Explain = linter.Explain
			}

			// Display itemized findings for structured details
			logStructuredDetails(log, details)

			results[pkgname].Findings[linterName] = append(results[pkgname].Findings[linterName], finding)

			errs = append(errs, fmt.Errorf("linter %q failed: %w", linterName, err))
		}
	}

	return errors.Join(errs...)
}

func checkLinters(linters []string) error {
	var errs []error
	for _, linterName := range linters {
		if _, found := linterMap[linterName]; !found {
			errs = append(errs, fmt.Errorf("unknown linter: %q", linterName))
		}
	}
	return errors.Join(errs...)
}

// saveLintResults saves the lint results to JSON files in the packages directory
func saveLintResults(ctx context.Context, cfg *config.Configuration, results map[string]*types.PackageLintResults, outputDir, arch string) error {
	log := clog.FromContext(ctx)

	// If cfg is nil, we can't determine version/epoch, so skip saving
	if cfg == nil {
		log.Warnf("skipping lint results persistence: configuration is nil")
		return nil
	}

	// Ensure the package directory exists
	packageDir := filepath.Join(outputDir, arch)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return fmt.Errorf("creating package directory: %w", err)
	}

	// Save results for each package
	for pkgName, pkgResults := range results {
		// Generate the filename: lint-{packagename}-{version}-r{epoch}.json
		filename := fmt.Sprintf("lint-%s-%s-r%d.json", pkgName, cfg.Package.Version, cfg.Package.Epoch)
		filepath := filepath.Join(packageDir, filename)

		// Marshal to JSON with indentation for readability
		jsonData, err := json.MarshalIndent(pkgResults, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling lint results for %s: %w", pkgName, err)
		}

		// Write to file
		if err := os.WriteFile(filepath, jsonData, 0o644); err != nil {
			return fmt.Errorf("writing lint results to %s: %w", filepath, err)
		}

		log.Infof("saved lint results to %s", filepath)
	}

	return nil
}

// Lint the given build directory at the given path
// Lint results will be stored as JSON in the packages directory
func LintBuild(ctx context.Context, cfg *config.Configuration, packageName string, require, warn []string, fsys apkofs.FullFS, outputDir, arch string) error {
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	// map of pkgname -> lint results
	results := make(map[string]*types.PackageLintResults)

	log := clog.FromContext(ctx)
	log.Infof("linting apk: %s", packageName)

	// Construct full package name with version and epoch
	var fullPackageName string
	if cfg != nil {
		fullPackageName = fmt.Sprintf("%s-%s-r%d", packageName, cfg.Package.Version, cfg.Package.Epoch)
	} else {
		fullPackageName = packageName
	}

	// Run warning linters - logs directly, ignores errors
	_ = lintPackageFS(ctx, cfg, packageName, fsys, warn, results, fullPackageName)

	// Run required linters - logs directly, returns errors
	lintErr := lintPackageFS(ctx, cfg, packageName, fsys, require, results, fullPackageName)

	// Save lint results to JSON file if there are any findings
	if len(results) > 0 {
		log.Infof("saving %d package lint result(s) to %s", len(results), filepath.Join(outputDir, arch))
		if err := saveLintResults(ctx, cfg, results, outputDir, arch); err != nil {
			log.Warnf("failed to save lint results: %v", err)
		}
	} else {
		log.Infof("no lint findings to persist for package %s", packageName)
	}

	return lintErr
}

// Lint the given APK at the given path
// If outputDir is provided, lint results will be saved to JSON files
func LintAPK(ctx context.Context, path string, require, warn []string, outputDir string) error {
	log := clog.FromContext(ctx)
	if err := checkLinters(append(require, warn...)); err != nil {
		return err
	}

	var r io.Reader
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
		if err != nil {
			return fmt.Errorf("creating HTTP request: %w", err)
		}
		if err := auth.DefaultAuthenticators.AddAuth(ctx, req); err != nil {
			return fmt.Errorf("adding authentication to request: %w", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("getting apk %q: %w", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("getting apk %q: %s", path, resp.Status)
		}
		defer resp.Body.Close()
		r = resp.Body
	} else {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("linting apk %q: %w", path, err)
		}
		defer file.Close()
		r = file
	}

	exp, err := expandapk.ExpandApk(ctx, r, "")
	if err != nil {
		return fmt.Errorf("expanding apk %q: %w", path, err)
	}
	defer exp.Close()

	// Get the package name and metadata
	f, err := exp.ControlFS.Open(".PKGINFO")
	if err != nil {
		return fmt.Errorf("could not open .PKGINFO file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read from package: %w", err)
	}

	pkginfo, err := ini.Load(data)
	if err != nil {
		return fmt.Errorf("could not load .PKGINFO file: %w", err)
	}

	section := pkginfo.Section("")
	pkgname := section.Key("pkgname").MustString("")
	if pkgname == "" {
		return fmt.Errorf("pkgname is nonexistent")
	}

	// Extract version and epoch for synthetic config (for JSON file naming)
	pkgver := section.Key("pkgver").MustString("")
	epochStr := section.Key("epoch").MustString("0")
	epoch, _ := strconv.Atoi(epochStr)

	// Extract architecture from PKGINFO
	arch := section.Key("arch").MustString("")

	cfg, err := parseMelangeYaml(exp.ControlFS)
	if err != nil {
		// TODO: Consider making this fatal if the universe gets rebuilt with new melange.
		clog.FromContext(ctx).Warnf("parsing .melange.yaml: %v", err)

		// Create a synthetic config for JSON file naming
		if cfg == nil && outputDir != "" {
			cfg = &config.Configuration{
				Package: config.Package{
					Version: pkgver,
					Epoch:   uint64(epoch),
				},
			}
		}
	}

	// Construct full package name with version and epoch
	fullPackageName := fmt.Sprintf("%s-%s-r%d", pkgname, pkgver, epoch)

	log.Infof("linting apk: %s (size: %s)", pkgname, humanize.Bytes(uint64(exp.Size)))

	// map of pkgname -> lint results
	results := make(map[string]*types.PackageLintResults)

	// Run warning linters - logs directly, ignores errors
	_ = lintPackageFS(ctx, cfg, pkgname, exp.TarFS, warn, results, fullPackageName)

	// Run required linters - logs directly, returns errors
	lintErr := lintPackageFS(ctx, cfg, pkgname, exp.TarFS, require, results, fullPackageName)

	// Save lint results to JSON file if outputDir is provided and there are findings
	if outputDir != "" && len(results) > 0 {
		log.Infof("saving %d package lint result(s) to %s", len(results), filepath.Join(outputDir, arch))
		if err := saveLintResults(ctx, cfg, results, outputDir, arch); err != nil {
			log.Warnf("failed to save lint results: %v", err)
		}
	} else if outputDir != "" {
		log.Infof("no lint findings to persist for package %s", pkgname)
	}

	return lintErr
}

func parseMelangeYaml(fsys fs.FS) (*config.Configuration, error) {
	my, err := fsys.Open(".melange.yaml")
	if err != nil {
		return nil, fmt.Errorf("could not open .melange.yaml file: %w", err)
	}
	defer my.Close()

	// We expect the file to be complete, so we don't need to post-process
	// it with any of the options available in ParseConfiguration.
	var cfg config.Configuration
	if err := yaml.NewDecoder(my).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func usrmergeLinter(ctx context.Context, _ *config.Configuration, _ string, fsys fs.FS) error {
	paths := []string{}
	dirs := []string{"sbin", "bin", "usr/sbin", "lib", "lib64"}

	pathInDir := func(path string, dirs ...string) bool {
		for _, d := range dirs {
			if path == d || strings.HasPrefix(path, d+"/") {
				return true
			}
		}
		return false
	}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if isIgnoredPath(path) {
			return filepath.SkipDir
		}

		// If it's not a directory of interest just skip the whole tree
		if !(path == "." || path == "usr" || pathInDir(path, dirs...)) {
			return filepath.SkipDir
		}

		if slices.Contains(dirs, path) {
			if d.IsDir() || d.Type().IsRegular() {
				paths = append(paths, path)
				return nil
			}
		}

		if pathInDir(path, dirs...) {
			paths = append(paths, path)
		}

		return nil
	})
	if err != nil {
		fmt.Print("Returned error?")
		return err
	}

	if len(paths) > 0 {
		details := &types.UsrMergeDetails{
			Paths: paths,
		}

		// Build human-readable message
		message := "Package contains paths in violation of usrmerge:"
		for _, path := range paths {
			message = strings.Join([]string{message, path}, "\n")
		}

		return types.NewStructuredError(message, details)
	}

	return nil
}

var isCudaDriverLibRegex = regexp.MustCompile(`^usr/lib/lib(cuda|nvidia-ml)\.so(\.[0-9]+)*$`)

func cudaDriverLibLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	return collectMatchingPaths(ctx, pkgname, fsys,
		func(path string) bool { return isCudaDriverLibRegex.MatchString(path) },
		func(pkgname string, paths []string) string {
			return fmt.Sprintf("%s contains CUDA driver-specific libraries", pkgname)
		},
	)
}
