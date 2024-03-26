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
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/chainguard-dev/clog"
	apkofs "github.com/chainguard-dev/go-apk/pkg/fs"
	"github.com/chainguard-dev/go-pkgconfig"

	"chainguard.dev/melange/pkg/config"
)

var libDirs = []string{"lib/", "usr/lib/", "lib64/", "usr/lib64/"}

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
}

// DependencyGenerator takes an SCAHandle and config.Dependencies pointer and returns
// findings based on analysis.
type DependencyGenerator func(context.Context, SCAHandle, *config.Dependencies) error

func allowedPrefix(path string, prefixes []string) bool {
	for _, pfx := range prefixes {
		if strings.HasPrefix(path, pfx) {
			return true
		}
	}

	return false
}

var cmdPrefixes = []string{"bin/", "sbin/", "usr/bin/", "usr/sbin/"}

func generateCmdProviders(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
	log := clog.FromContext(ctx)
	if hdl.Options().NoCommands {
		return nil
	}

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

		if mode.Perm()&0555 == 0555 {
			if allowedPrefix(path, cmdPrefixes) {
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
func dereferenceCrossPackageSymlink(hdl SCAHandle, path string) (string, string, error) {
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

	for _, pkgName := range targetPackageNames {
		baseFS, err := hdl.FilesystemForRelative(pkgName)
		if err != nil {
			return "", "", err
		}

		for _, libDir := range libDirs {
			testPath := filepath.Join(libDir, realPath)

			if _, err := baseFS.Stat(testPath); err == nil {
				return pkgName, testPath, nil
			}
		}
	}

	return "", "", nil
}

func generateSharedObjectNameDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for shared object dependencies...")

	depends := map[string][]string{}
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

		// If it is a symlink, lets check and see if it is a library SONAME.
		if mode.Type()&fs.ModeSymlink == fs.ModeSymlink {
			if !strings.Contains(path, ".so") {
				return nil
			}

			targetPkg, realPath, err := dereferenceCrossPackageSymlink(hdl, path)
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

					if !hdl.Options().NoDepends {
						generated.Runtime = append(generated.Runtime, fmt.Sprintf("so:%s", soname))
					}
				}
			}

			return nil
		}

		// If it is not a regular file, we are finished processing it.
		if !mode.IsRegular() {
			return nil
		}

		if mode.Perm()&0555 != 0555 {
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
		if interp != "" && !hdl.Options().NoDepends {
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

		if !hdl.Options().NoDepends {
			for _, lib := range libs {
				if strings.Contains(lib, ".so.") {
					log.Infof("  found lib %s for %s", lib, path)
					generated.Runtime = append(generated.Runtime, fmt.Sprintf("so:%s", lib))
					depends[lib] = append(depends[lib], path)
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
		if interp == "" || strings.Contains(basename, ".so.") {
			sonames, err := ef.DynString(elf.DT_SONAME)
			// most likely SONAME is not set on this object
			if err != nil {
				log.Warnf("library %s lacks SONAME", path)
				return nil
			}

			for _, soname := range sonames {
				libver := sonameLibver(soname)

				if allowedPrefix(path, libDirs) {
					generated.Provides = append(generated.Provides, fmt.Sprintf("so:%s=%s", soname, libver))
				} else {
					generated.Vendored = append(generated.Vendored, fmt.Sprintf("so:%s=%s", soname, libver))
				}
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

var pkgConfigVersionRegexp = regexp.MustCompile("-(alpha|beta|rc|pre)")

// TODO(kaniini): Turn this feature on once enough of Wolfi is built with provider data.
var generateRuntimePkgConfigDeps = false

var pcDirs = []string{"lib/pkgconfig/", "usr/lib/pkgconfig/", "lib64/pkgconfig/", "usr/lib64/pkgconfig/"}

// generatePkgConfigDeps generates a list of provided pkg-config package names and versions,
// as well as dependency relationships.
func generatePkgConfigDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
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

		apkVersion := pkgConfigVersionRegexp.ReplaceAllString(pkg.Version, "_$1")
		if !hdl.Options().NoProvides {
			if allowedPrefix(path, pcDirs) {
				log.Infof("  found pkg-config %s for %s", pcName, path)
				generated.Provides = append(generated.Provides, fmt.Sprintf("pc:%s=%s", pcName, apkVersion))
			} else {
				log.Infof("  found vendored pkg-config %s for %s", pcName, path)
				generated.Vendored = append(generated.Vendored, fmt.Sprintf("pc:%s=%s", pcName, apkVersion))
			}
		}

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

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// generatePythonDeps generates a python3~$VERSION dependency for packages which ship
// Python modules.
func generatePythonDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
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

// Analyze runs the SCA analyzers on a given SCA handle, modifying the generated dependencies
// set as needed.
func Analyze(ctx context.Context, hdl SCAHandle, generated *config.Dependencies) error {
	if hdl.Options().NoProvides {
		return nil
	}
	generators := []DependencyGenerator{
		generateSharedObjectNameDeps,
		generateCmdProviders,
		generatePkgConfigDeps,
		generatePythonDeps,
	}

	for _, gen := range generators {
		if err := gen(ctx, hdl, generated); err != nil {
			return err
		}
	}

	return nil
}
