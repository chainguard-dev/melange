// Copyright 2022 Chainguard, Inc.
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
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"chainguard.dev/apko/pkg/apk/apk"
	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/go-pkgconfig"

	"chainguard.dev/melange/pkg/config"
)

// LibDirs is the list of library directories to search for shared objects.
// This is exported so that callers can append to it as needed.
var LibDirs = []string{"lib/", "usr/lib/", "lib64/", "usr/lib64/"}

// BinDirs is the list of binary directories to search for commands.
// This is exported so that callers can append to it as needed.
var BinDirs = []string{"bin/", "sbin/", "usr/bin/", "usr/sbin/"}

// SCAFS represents the minimum required filesystem accessors which are needed by
// the SCA engine.
type SCAFS interface {
	apkofs.ReadLinkFS

	Stat(name string) (fs.FileInfo, error)
}

// SCAHandle represents all of the state necessary to analyze a package.
type SCAHandle interface {
	// PackageName returns the name of the current package being analyzed.
	PackageName() string

	// RelativeNames returns the name of other packages related to the current
	// package being analyzed.
	RelativeNames() []string

	// Version returns the version and epoch of the package being analyzed.
	Version() string

	// FilesystemForRelative returns a usable filesystem representing the package
	// contents for a given package name.
	FilesystemForRelative(pkgName string) (SCAFS, error)

	// Filesystem returns a usable filesystem representing the current package.
	// It is equivalent to FilesystemForRelative(PackageName()).
	Filesystem() (SCAFS, error)

	// Options returns a config.PackageOption struct.
	Options() config.PackageOption

	// BaseDependencies returns the underlying set of declared dependencies before
	// the SCA engine runs.
	BaseDependencies() config.Dependencies

	// InstalledPackages returns a map [package name] => [package
	// version] for all build dependencies installed during build.
	InstalledPackages() map[string]string

	// PkgResolver returns the package resolver associated with
	// the current package/build being analyzed.
	PkgResolver() *apk.PkgResolver
}

// DependencyGenerator takes an SCAHandle, config.Dependencies pointer
// and a list of paths to be appended to LibDirs and returns findings
// based on analysis.
type DependencyGenerator func(context.Context, SCAHandle, *config.Dependencies, []string) error

func isInDir(path string, dirs []string) bool {
	mydir := filepath.Dir(path)
	for _, d := range dirs {
		// allow the /... suffix (i.e. "usr/...") to indicate recursive matching
		if prefix, ok := strings.CutSuffix(d, "/..."); ok {
			// Ensure we match the directory exactly or as a prefix followed by /
			// This prevents /dir matching /dirother
			if mydir == prefix || strings.HasPrefix(mydir, prefix+"/") {
				return true
			}
		} else if mydir == d || mydir+"/" == d {
			return true
		}
	}
	return false
}

// isHostProvidedLibrary returns true if the library is provided by the host
// system and should not be included in dependency or provides generation.
// These are typically NVIDIA libraries that are installed by the host driver.
func isHostProvidedLibrary(lib string) bool {
	hostLibs := []string{
		"libEGL_nvidia.so.1",
		"libGLESv1_CM_nvidia.so.1",
		"libGLESv2_nvidia.so.1",
		"libGLX_nvidia.so.1",
		"libcuda.so.1",
		"libcudadebugger.so.1",
		"libnvcuvid.so.1",
		"libnvidia-allocator.so.1",
		"libnvidia-cfg.so.1",
		"libnvidia-eglcore.so.1",
		"libnvidia-encode.so.1",
		"libnvidia-fbc.so.1",
		"libnvidia-glcore.so.1",
		"libnvidia-glsi.so.1",
		"libnvidia-glvkspirv.so.1",
		"libnvidia-gpucomp.so.1",
		"libnvidia-ml.so.1",
		"libnvidia-ngx.so.1",
		"libnvidia-nvvm.so.1",
		"libnvidia-opencl.so.1",
		"libnvidia-opticalflow.so.1",
		"libnvidia-pkcs11-openssl3.so.1",
		"libnvidia-pkcs11.so.1",
		"libnvidia-ptxjitcompiler.so.1",
		"libnvidia-rtcore.so.1",
		"libnvidia-tls.so.1",
		"libnvoptix.so.1",
	}

	return slices.Contains(hostLibs, lib)
}

// getLdSoConfDLibPaths will iterate over the files being installed by
// the package and all its subpackages, and for each configuration
// file found under /etc/ld.so.conf.d/ it will parse the file and add
// its contents to a string vector.  This vector will ultimately
// contain all extra paths that will be considered by ld when doing
// symbol resolution.
func getLdSoConfDLibPaths(ctx context.Context, hdl SCAHandle) ([]string, error) {
	var extraLibPaths []string
	targetPackageNames := hdl.RelativeNames()

	log := clog.FromContext(ctx)

	log.Info("scanning for ld.so.conf.d files...")

	for _, pkgName := range targetPackageNames {
		fsys, err := hdl.FilesystemForRelative(pkgName)
		if err != nil {
			return nil, err
		}

		if err := fs.WalkDir(fsys, "etc/ld.so.conf.d", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fs.SkipAll
				}
				return err
			}

			// We're only interested in files whose suffix is ".conf"
			if !strings.HasSuffix(path, ".conf") {
				return nil
			}

			fi, err := d.Info()
			if err != nil {
				return err
			}

			if !fi.Mode().IsRegular() {
				return nil
			}

			log.Infof("  found ld.so.conf.d file %s", path)

			fd, err := fsys.Open(path)
			if err != nil {
				return err
			}
			defer fd.Close()

			scanner := bufio.NewScanner(fd)
			for scanner.Scan() {
				line := scanner.Text()
				if line == "" || line[0] != '/' {
					continue
				}
				// Strip the initial slash since
				// LibDirs paths need to be relative.
				line = line[1:]
				log.Infof("    found extra lib path %s", line)
				extraLibPaths = append(extraLibPaths, line)
			}

			if err := scanner.Err(); err != nil {
				return err
			}

			return nil
		}); err != nil {
			return nil, err
		}
	}

	return extraLibPaths, nil
}

func generateCmdProviders(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)

	log.Info("scanning for commands...")
	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()
		if !mode.IsRegular() {
			return nil
		}

		if mode.Perm()&0o555 == 0o555 {
			if isInDir(path, BinDirs) {
				basename := filepath.Base(path)
				log.Infof("  found command %s", path)
				generated.Provides = append(generated.Provides, fmt.Sprintf("cmd:%s=%s", basename, hdl.Version()))
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// findInterpreter looks for the PT_INTERP header and extracts the interpreter so that it
// may be used as a dependency.
func findInterpreter(bin *elf.File) (string, error) {
	for _, prog := range bin.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}

		reader := prog.Open()
		interpBuf, err := io.ReadAll(reader)
		if err != nil {
			return "", err
		}

		interpBuf = bytes.Trim(interpBuf, "\x00")
		return string(interpBuf), nil
	}

	return "", nil
}

// dereferenceCrossPackageSymlink attempts to dereference a symlink across multiple package
// directories.
func dereferenceCrossPackageSymlink(hdl SCAHandle, path string, extraLibDirs []string) (string, string, error) {
	targetPackageNames := hdl.RelativeNames()

	pkgFS, err := hdl.Filesystem()
	if err != nil {
		return "", "", err
	}

	realPath, err := pkgFS.Readlink(path)
	if err != nil {
		return "", "", err
	}

	realPath = filepath.Base(realPath)

	expandedLibDirs := append([]string{}, LibDirs...)
	expandedLibDirs = append(expandedLibDirs, extraLibDirs...)

	for _, pkgName := range targetPackageNames {
		baseFS, err := hdl.FilesystemForRelative(pkgName)
		if err != nil {
			return "", "", err
		}

		for _, libDir := range expandedLibDirs {
			testPath := filepath.Join(libDir, realPath)

			if _, err := baseFS.Stat(testPath); err == nil {
				return pkgName, testPath, nil
			}
		}
	}

	return "", "", nil
}

// determineShlibVersion tries to determine the exact version of the
// package that provides the shared library shlib.  It does that by:
//
// - Asking PkgResolver to calculate the list of packages that provide "so:shlib".
//
//   - Verifying if any package in that list matches what is currently
//     installed in the build environment.  The package can offer a
//     provided shared library whose version is equal or greater than
//     the one the build requires.
//
//   - Verifying if the matched package has a versioned shared library
//     "provides:".
//
// If all steps succeed, the package version is returned.
//
// If there is a match but the package doesn't currently offer a
// versioned shared library "provides:", then an empty version is
// returned.  We can't do versioned "depends:" unless there is a
// matching "provides:".
//
// If no match is found, then we assume that the shared library is
// vendored by the package being built.  In this case, we return an
// empty version string.
func determineShlibVersion(ctx context.Context, hdl SCAHandle, shlib string) (string, error) {
	log := clog.FromContext(ctx)

	// Feature flag to disable versioned shlib dependencies.
	if os.Getenv("MELANGE_VERSIONED_SHLIB_DEPENDS") == "" {
		return "", nil
	}

	if hdl.Options().NoVersionedShlibDeps {
		// This package does not care about versioned shlib
		// depends.
		return "", nil
	}

	// We don't version-depend or provide ld-linux-*.so, otherwise
	// we'd be required to rebuild all packages that link against
	// glibc whenever the latter is updated.
	if strings.HasPrefix(shlib, "ld-linux-x86-64.so") || strings.HasPrefix(shlib, "ld-linux-aarch64.so") {
		log.Debugf("Skipping %s", shlib)
		return "", nil
	}

	pkgResolver := hdl.PkgResolver()

	if pkgResolver == nil {
		// When we're invoked from "melange scan", there's no
		// package resolver available.  Just return an empty
		// version.
		log.Debugf("Package resolver is nil; returning an empty shlib version")
		return "", nil
	}

	// Obtain the list of packages that provide the shared
	// library.
	candidates, err := pkgResolver.ResolvePackage("so:"+shlib, map[*apk.RepositoryPackage]string{})
	if err != nil {
		if strings.Contains(err.Error(), "nothing provides") {
			// We can reach here if one of the
			// (sub)packages we're building provides a new
			// version of a shared library.  Since this
			// new (sub)package isn't present in the
			// current APKINDEX, ResolvePackage() won't be
			// able to find it.  However, we can return
			// the current version being built in this
			// case.
			return hdl.Version(), nil
		}

		// This is an unknown error, so we'd better return it.
		return "", err
	}

	// ResolvePackage will return *all* packages that provide
	// shlib, including those that have been obsoleted.  For that
	// reason, we need sort the list of candidates by build time,
	// making sure that we're always considering the newest ones.
	slices.SortFunc(candidates, func(p1 *apk.RepositoryPackage, p2 *apk.RepositoryPackage) int {
		return p2.BuildTime.Compare(p1.BuildTime)
	})

	// Obtain the list of packages currently installed in the
	// build environment.
	pkgVersionMap := hdl.InstalledPackages()

	for _, candidate := range candidates {
		log.Debugf("Verifying if package %s-%s (which provides shlib %s) is the one used to build the package", candidate.PackageName(), candidate.Version, shlib)

		// The version of the package that's installed in the
		// build environment.
		installedPackageVersionString, ok := pkgVersionMap[candidate.PackageName()]
		if !ok {
			// We don't have the candidate package in the
			// build environment.  That can happen
			// e.g. when multiple packages provide the
			// same shared library.
			//
			// Ideally we will see the correct package
			// later in the loop.
			continue
		}

		if installedPackageVersionString == "@CURRENT@" {
			// This is the package (or one of its
			// subpackages) being built.  Return the
			// current version as it is equal or greater
			// than the one currently in the index.
			return hdl.Version(), nil
		} else {
			// Convert the versions of the candidate and
			// installed packages to proper structures so
			// that we can compare them.
			candidateVersion, err := apk.ParseVersion(candidate.Version)
			if err != nil {
				return "", err
			}
			installedPackageVersion, err := apk.ParseVersion(installedPackageVersionString)
			if err != nil {
				return "", err
			}

			if apk.CompareVersions(candidateVersion, installedPackageVersion) < 0 {
				// The candidate package provides an
				// shlib that is versioned as older
				// than the one we have in our build
				// environment.
				return "", fmt.Errorf("could not find suitable package providing library so-ver:%s>=%s (found so-ver:%s=%s instead)", shlib, installedPackageVersionString, shlib, candidate.Version)
			}

			// Check if the package actually provides a
			// versioned shlib, otherwise we can't depend on it.
			if slices.ContainsFunc(candidate.Provides, func(provides string) bool {
				providedArtifact, providedVersion, found := strings.Cut(provides, "=")
				if !found {
					return false
				}

				if providedArtifact != "so-ver:"+shlib {
					return false
				}

				_, err := apk.ParseVersion(providedVersion)
				// If we're able to parse the version,
				// then it's a valid one.
				return err != nil
			}) {
				return installedPackageVersionString, nil
			}

			// The package (still) doesn't provide a
			// versioned shlib.  That's ok; just return an
			// empty version for now.
			return "", nil
		}
	}

	// If we're here, then one of the following scenarios happened:
	//
	// - The list of candidates is empty.  This happens when we're
	//   dealing with a vendored shared library that isn't
	//   provided by any of our packages.  Just return an empty
	//   version string.
	//
	// - There is a list of candidates, but none of them provides
	//   the version of shared library we're interested in.  This
	//   has been seen to happen when the package being built uses
	//   a vendored library that *is* provided by one of our
	//   packages, but the vendored version is higher than the
	//   non-vendored one.  This is also a case of vendorization,
	//   so we return an empty version string.
	return "", nil
}

func processSymlinkSo(ctx context.Context, hdl SCAHandle, path string, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	if !strings.Contains(path, ".so") {
		return nil
	}

	targetPkg, realPath, err := dereferenceCrossPackageSymlink(hdl, path, extraLibDirs)
	if err != nil {
		return nil
	}

	targetFS, err := hdl.FilesystemForRelative(targetPkg)
	if err != nil {
		return nil
	}

	if realPath != "" {
		rawFile, err := targetFS.Open(realPath)
		if err != nil {
			return nil
		}
		defer rawFile.Close()

		seekableFile, ok := rawFile.(io.ReaderAt)
		if !ok {
			return nil
		}

		ef, err := elf.NewFile(seekableFile)
		if err != nil {
			return nil
		}
		defer ef.Close()

		sonames, err := ef.DynString(elf.DT_SONAME)
		// most likely SONAME is not set on this object
		if err != nil {
			log.Warnf("library %s lacks SONAME", path)
			return nil
		}

		for _, soname := range sonames {
			log.Infof("  found soname %s for %s", soname, path)

			generated.Runtime = append(generated.Runtime, fmt.Sprintf("so:%s", soname))

			shlibVer, err := determineShlibVersion(ctx, hdl, soname)
			if err != nil {
				return err
			}
			if shlibVer != "" {
				generated.Runtime = append(generated.Runtime, fmt.Sprintf("so-ver:%s>=%s", soname, shlibVer))
			}
		}
	}

	return nil
}

func generateSharedObjectNameDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for shared object dependencies...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	expandedLibDirs := append([]string{}, LibDirs...)
	expandedLibDirs = append(expandedLibDirs, extraLibDirs...)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()

		// If it is a symlink, lets check and see if it is a library SONAME.
		isLink := mode.Type()&fs.ModeSymlink == fs.ModeSymlink

		if isLink {
			if err := processSymlinkSo(ctx, hdl, path, generated, extraLibDirs); err != nil {
				return err
			}
		}

		// If it is not a regular file, we are finished processing it.
		if !mode.IsRegular() && !isLink {
			return nil
		}

		basename := filepath.Base(path)

		// most likely a shell script instead of an ELF, so treat any
		// error as non-fatal.
		rawFile, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		defer rawFile.Close()

		seekableFile, ok := rawFile.(io.ReaderAt)
		if !ok {
			return nil
		}

		ef, err := elf.NewFile(seekableFile)
		if err != nil {
			return nil
		}
		defer ef.Close()

		interp, err := findInterpreter(ef)
		if err != nil {
			return err
		}
		if interp != "" {
			log.Infof("interpreter for %s => %s", basename, interp)

			// musl interpreter is a symlink back to itself, so we want to use the non-symlink name as
			// the dependency.
			interpName := fmt.Sprintf("so:%s", filepath.Base(interp))
			interpName = strings.ReplaceAll(interpName, "so:ld-musl", "so:libc.musl")
			generated.Runtime = append(generated.Runtime, interpName)
		}

		libs, err := ef.ImportedLibraries()
		if err != nil {
			log.Warnf("WTF: ImportedLibraries() returned error: %v", err)
			return nil
		}

		for _, lib := range libs {
			// These are dangling libraries, which must come from the host
			if isHostProvidedLibrary(lib) {
				continue
			}
			if strings.Contains(lib, ".so.") {
				log.Infof("  found lib %s for %s", lib, path)
				generated.Runtime = append(generated.Runtime, fmt.Sprintf("so:%s", lib))

				shlibVer, err := determineShlibVersion(ctx, hdl, lib)
				if err != nil {
					return err
				}
				if shlibVer != "" {
					generated.Runtime = append(generated.Runtime, fmt.Sprintf("so-ver:%s>=%s", lib, shlibVer))
				}
			}
		}

		// An executable program should never have a SONAME, but apparently binaries built
		// with some versions of jlink do.  Thus, if an interpreter is set (meaning it is an
		// executable program), we do not scan the object for SONAMEs.
		//
		// Unfortunately, some shared objects are intentionally also executables.
		//
		// For example:
		// - libc has an PT_INTERP set on itself to make `/lib/libc.so.6 --about` work.
		// - libcap does this to make `/usr/lib/libcap.so.2 --summary` work.
		//
		// See https://stackoverflow.com/a/68339111/14760867 for some more context.
		//
		// As a rough heuristic, we assume that if the filename contains ".so.",
		// it is meant to be used as a shared object.
		if interp == "" || strings.Contains(basename, ".so.") || strings.HasSuffix(basename, ".so") {
			sonames, err := ef.DynString(elf.DT_SONAME)
			// most likely SONAME is not set on this object
			if err != nil {
				log.Warnf("library %s lacks SONAME", path)
				return nil
			}

			for _, soname := range sonames {
				// Packages should not provide these shared objects because they
				// will conflict with the driver injected by the host.
				if isHostProvidedLibrary(soname) {
					continue
				}

				libver := sonameLibver(soname)

				if isInDir(path, expandedLibDirs) {
					generated.Provides = append(generated.Provides, fmt.Sprintf("so:%s=%s", soname, libver))
					generated.Provides = append(generated.Provides, fmt.Sprintf("so-ver:%s=%s", soname, hdl.Version()))
				} else {
					generated.Vendored = append(generated.Vendored, fmt.Sprintf("so:%s=%s", soname, libver))
					generated.Vendored = append(generated.Vendored, fmt.Sprintf("so-ver:%s=%s", soname, hdl.Version()))
				}
			}
		}

		// check if it is a go binary
		buildinfo, err := buildinfo.Read(seekableFile)
		if err != nil {
			return nil
		}
		var cgo, fipscrypto bool
		// current RHEL/golang-fips; current microsoft/go; old microsoft/go
		fipsexperiments := []string{"boringcrypto", "systemcrypto", "opensslcrypto"}
		for _, setting := range buildinfo.Settings {
			if setting.Key == "CGO_ENABLED" && setting.Value == "1" {
				cgo = true
			}
			if setting.Key == "GOEXPERIMENT" && slices.Contains(fipsexperiments, setting.Value) {
				fipscrypto = true
			}
			if setting.Key == "microsoft_systemcrypto" && setting.Value == "1" {
				fipscrypto = true
			}
		}
		// strong indication of go-fips openssl compiled binary, will dlopen the below at runtime
		if cgo && fipscrypto {
			generated.Runtime = append(generated.Runtime, "openssl-config-fipshardened")
			generated.Runtime = append(generated.Runtime, "so:libcrypto.so.3")
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// TODO(xnox): Note remove this feature flag, once successful
// note this can generate depends on pc: files that do not exist in
// wolfi, however package install tests will catch that in presubmit
var generateRuntimePkgConfigDeps = true

// generatePkgConfigDeps generates a list of provided pkg-config package names and versions,
// as well as dependency relationships.
func generatePkgConfigDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for pkg-config data...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".pc") {
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()

		// Sigh.  ncurses uses symlinks to alias .pc files to other .pc files.
		// Skip the symlinks for now.
		if mode.Type()&fs.ModeSymlink == fs.ModeSymlink {
			return nil
		}

		// TODO(kaniini): Sigh.  apkofs should have ReadFile by default.
		dataFile, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		defer dataFile.Close()

		data, err := io.ReadAll(dataFile)
		if err != nil {
			return nil
		}

		// TODO(kaniini): Sigh.  go-pkgconfig should support reading from any io.Reader.
		pkg, err := pkgconfig.Parse(string(data))
		if err != nil {
			log.Warnf("Unable to load .pc file (%s) using pkgconfig: %v", path, err)
			return nil
		}

		pcName := filepath.Base(path)
		pcName, _ = strings.CutSuffix(pcName, ".pc")

		if isInDir(path, []string{"usr/local/lib/pkgconfig/", "usr/local/share/pkgconfig/", "usr/lib/pkgconfig/", "usr/lib64/pkgconfig/", "usr/share/pkgconfig/"}) {
			log.Infof("  found pkg-config %s for %s", pcName, path)
			generated.Provides = append(generated.Provides, fmt.Sprintf("pc:%s=%s", pcName, hdl.Version()))

			if generateRuntimePkgConfigDeps {
				// TODO(kaniini): Capture version relationships here too.  In practice, this does not matter
				// so much though for us.
				for _, dep := range pkg.Requires {
					log.Infof("  found pkg-config dependency (requires) %s for %s", dep.Identifier, path)
					generated.Runtime = append(generated.Runtime, fmt.Sprintf("pc:%s", dep.Identifier))
				}

				for _, dep := range pkg.RequiresPrivate {
					log.Infof("  found pkg-config dependency (requires private) %s for %s", dep.Identifier, path)
					generated.Runtime = append(generated.Runtime, fmt.Sprintf("pc:%s", dep.Identifier))
				}

				for _, dep := range pkg.RequiresInternal {
					log.Infof("  found pkg-config dependency (requires internal) %s for %s", dep.Identifier, path)
					generated.Runtime = append(generated.Runtime, fmt.Sprintf("pc:%s", dep.Identifier))
				}
			}
		} else {
			log.Infof("  found vendored pkg-config %s for %s", pcName, path)
			generated.Vendored = append(generated.Vendored, fmt.Sprintf("pc:%s=%s", pcName, hdl.Version()))
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// generatePythonDeps generates a python-3.X-base dependency for packages which ship
// Python modules.
func generatePythonDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for python modules...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	var pythonModuleVer string
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Python modules are installed in paths such as /usr/lib/pythonX.Y/site-packages/...,
		// so if we find a directory named site-packages, and its parent is a pythonX.Y directory,
		// then we have a Python module directory.
		basename := filepath.Base(path)
		if basename != "site-packages" {
			return nil
		}

		parent := filepath.Dir(path)
		basename = filepath.Base(parent)
		if !strings.HasPrefix(basename, "python") {
			return nil
		}

		// This probably shouldn't ever happen, but lets check to make sure.
		if !d.IsDir() {
			return nil
		}

		// This takes the X.Y part of the pythonX.Y directory name as the version to pin against.
		// If the X.Y part is not present, then pythonModuleVer will remain an empty string and
		// no dependency will be generated.
		pythonModuleVer = basename[6:]
		return nil
	}); err != nil {
		return err
	}

	// Nothing to do...
	if pythonModuleVer == "" {
		return nil
	}

	// Do not add a Python dependency if one already exists.
	for _, dep := range hdl.BaseDependencies().Runtime {
		if strings.HasPrefix(dep, "python") {
			log.Warnf("%s: Python dependency %q already specified, consider removing it in favor of SCA-generated dependency", hdl.PackageName(), dep)
			return nil
		}
	}

	log.Infof("  found python module, generating python-%s-base dependency", pythonModuleVer)
	generated.Runtime = append(generated.Runtime, fmt.Sprintf("python-%s-base", pythonModuleVer))

	return nil
}

// generateRubyDeps generates a ruby-X.Y dependency for packages which ship
// Ruby gems.
func generateRubyDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for ruby gems...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	rubyGemMatches, err := fs.Glob(fsys, "usr/lib/ruby/gems/[0-9]*.[0-9]*.[0.9]*/gems")
	if err != nil {
		return err
	}
	if len(rubyGemMatches) == 0 {
		return nil
	}

	// This takes the first X.Y part of the usr/lib/ruby/gems/X.Y.Z directory name
	// as the version to pin against.
	majorMinorMicro := filepath.Base(filepath.Dir(rubyGemMatches[0]))
	rubyGemVer := strings.TrimSuffix(majorMinorMicro, filepath.Ext(majorMinorMicro))

	// Nothing to do...
	if rubyGemVer == "" {
		return nil
	}

	// Do not add a Ruby dependency if one already exists.
	for _, dep := range hdl.BaseDependencies().Runtime {
		if strings.HasPrefix(dep, "ruby-") {
			log.Warnf("%s: Ruby dependency %q already specified, consider removing it in favor of SCA-generated dependency", hdl.PackageName(), dep)
			return nil
		}

		if dep == "ruby" {
			log.Warnf("%s: Ruby dependency already specified", hdl.PackageName())
			return nil
		}
	}

	log.Infof("  found ruby gem, generating ruby-%s dependency", rubyGemVer)
	generated.Runtime = append(generated.Runtime, fmt.Sprintf("ruby-%s", rubyGemVer))

	return nil
}

// For a documentation package add a dependency on man-db and / or texinfo as appropriate
func generateDocDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for -doc package...")
	if !strings.HasSuffix(hdl.PackageName(), "-doc") {
		return nil
	}

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if isInDir(path, []string{"usr/share/man"}) {
			// Do not add a man-db dependency if one already exists.
			for _, dep := range hdl.BaseDependencies().Runtime {
				if dep == "man-db" {
					log.Warnf("%s: man-db dependency already specified, consider removing it in favor of SCA-generated dependency", hdl.PackageName())
				}
			}

			log.Infof("  found files in /usr/share/man/ in package, generating man-db dependency")
			generated.Runtime = append(generated.Runtime, "man-db")
		}

		if isInDir(path, []string{"usr/share/info"}) {
			// Do not add a texinfo dependency if one already exists.
			for _, dep := range hdl.BaseDependencies().Runtime {
				if dep == "texinfo" {
					log.Warnf("%s: texinfo dependency already specified, consider removing it in favor of SCA-generated dependency", hdl.PackageName())
				}
			}

			log.Infof("  found files in /usr/share/info/ in package, generating texinfo dependency")
			generated.Runtime = append(generated.Runtime, "texinfo")
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

func sonameLibver(soname string) string {
	parts := strings.Split(soname, ".so.")
	if len(parts) < 2 {
		return "0"
	}

	libver := parts[1]
	for _, r := range libver {
		if r != '.' && !unicode.IsDigit(r) {
			// Not a number, 0 should be fine?
			// TODO: Consider looking at filename?
			return "0"
		}
	}

	return libver
}

func getShbang(fp io.Reader) (string, error) {
	// python3 and sh are symlinks and generateCmdProviders currently only considers
	// regular files. Since nothing will fulfill such a depend, do not generate one.
	//
	// There are multiple variants of luajit; one maintained by OpenResty, and several
	// per each fluent-bit stream. We don't want to pull in the incorrect variant so do
	// not generate a dependency on cmd:luajit when found in a shebang.
	ignores := map[string]bool{"python3": true, "python": true, "sh": true, "awk": true, "luajit": true}

	buf := make([]byte, 80)
	blen, err := io.ReadFull(fp, buf)
	switch {
	case errors.Is(err, io.EOF):
		return "", nil
	case errors.Is(err, io.ErrUnexpectedEOF):
		if blen < 2 {
			return "", nil
		}
	case err != nil:
		return "", err
	}

	if !bytes.HasPrefix(buf, []byte("#!")) {
		return "", nil
	}

	line1 := string(buf[2:blen])
	endl := strings.Index(line1, "\n")
	if endl >= 0 {
		line1 = line1[:endl]
	}
	toks := strings.Fields(line1)
	if len(toks) == 0 {
		// Empty shebang line (just "#!" with whitespace)
		return "", nil
	}
	bin := toks[0]

	// if #! is '/usr/bin/env foo', then use next arg as the dep
	if bin == "/usr/bin/env" {
		switch {
		case len(toks) == 1:
			return "", fmt.Errorf("a shbang of only '/usr/bin/env'")
		case len(toks) == 2:
			bin = toks[1]
		case len(toks) >= 3 && toks[1] == "-S" && !strings.HasPrefix(toks[2], "-"):
			bin = toks[2]
		default:
			return "", fmt.Errorf("a shbang of only '/usr/bin/env' with multiple arguments (%d %s)", len(toks), strings.Join(toks, " "))
		}
	}

	if isIgnored := ignores[filepath.Base(bin)]; isIgnored {
		return "", nil
	}

	return bin, nil
}

func generateShbangDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for shbang deps...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	cmds := map[string]string{}
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.Type()&fs.ModeSymlink == fs.ModeSymlink {
			return nil
		}

		if !strings.HasPrefix(path, "usr/bin/") &&
			!strings.HasPrefix(path, "usr/local/bin/") &&
			!strings.HasPrefix(path, "usr/local/sbin/") {
			return nil
		}

		if d.Type().IsDir() {
			return nil
		}

		if fp, err := fsys.Open(path); err == nil {
			shbang, err := getShbang(fp)
			if err != nil {
				log.Warnf("Error reading shbang from %s: %v", path, err)
			} else if shbang != "" {
				cmds[filepath.Base(shbang)] = path
			}
			if err := fp.Close(); err != nil {
				log.Warnf("Error closing %s: %v", path, err)
			}
		} else {
			log.Infof("Failed to open %s: %v", path, err)
		}
		return nil
	}); err != nil {
		return err
	}

	for base, path := range cmds {
		log.Infof("Added shbang dep cmd:%s for %s", base, path)
		generated.Runtime = append(generated.Runtime, "cmd:"+base)
	}

	return nil
}

// Analyze runs the SCA analyzers on a given SCA handle, modifying the generated dependencies
// set as needed.
func Analyze(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
	extraLibDirs, err := getLdSoConfDLibPaths(ctx, hdl)
	if err != nil {
		return err
	}

	generators := []DependencyGenerator{
		generateSharedObjectNameDeps,
		generateCmdProviders,
		generateDocDeps,
		generatePkgConfigDeps,
		generatePythonDeps,
		generateRubyDeps,
		generateShbangDeps,
		generateKernelDeps,
	}

	for _, gen := range generators {
		if err := gen(ctx, hdl, generated, extraLibDirs); err != nil {
			return err
		}
	}

	generated.Runtime = slices.Compact(slices.Sorted(slices.Values(generated.Runtime)))
	generated.Provides = slices.Compact(slices.Sorted(slices.Values(generated.Provides)))
	generated.Vendored = slices.Compact(slices.Sorted(slices.Values(generated.Vendored)))

	if hdl.Options().NoCommands {
		generated.Provides = slices.DeleteFunc(generated.Provides, func(s string) bool {
			return strings.HasPrefix(s, "cmd:")
		})

		generated.Runtime = slices.DeleteFunc(generated.Runtime, func(s string) bool {
			return strings.HasPrefix(s, "cmd:")
		})
	}

	if hdl.Options().NoDepends {
		generated.Runtime = nil
	}

	if hdl.Options().NoProvides {
		generated.Provides = nil
	}

	return nil
}
