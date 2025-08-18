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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"chainguard.dev/melange/pkg/config"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
)

func TestLinters(t *testing.T) {
	mkfile := func(t *testing.T, path string) func() string {
		return func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, filepath.Dir(path)), 0o700))
			f, err := os.Create(filepath.Join(d, path))
			assert.NoError(t, err)
			fmt.Fprintln(f, "blah")
			defer f.Close()
			return d
		}
	}

	cfg := &config.Configuration{
		Package: config.Package{
			Name: "pkgconf",
		},
	}

	tpkgconfCfg := &config.Configuration{
		Package: config.Package{
			Name: "pkgconf",
		},
		Test: &config.Test{
			Pipeline: []config.Pipeline{{
				Uses: "test/pkgconf",
			}},
		},
	}

	subpkgtpkgconfCfg := &config.Configuration{
		Package: config.Package{
			Name: "not-pkgconf",
		},
		Subpackages: []config.Subpackage{{
			Name: "also-not-pkgconf",
		}, {
			Name: "pkgconf",
			Test: &config.Test{
				Pipeline: []config.Pipeline{{
					Uses: "test/pkgconf",
				}},
			},
		}},
	}

	tlddcheckCfg := &config.Configuration{
		Package: config.Package{
			Name: "lddcheck",
		},
		Test: &config.Test{
			Pipeline: []config.Pipeline{{
				Uses: "test/ldd-check",
			}},
		},
	}

	ttwlddcheckCfg := &config.Configuration{
		Package: config.Package{
			Name: "lddcheck",
		},
		Test: &config.Test{
			Pipeline: []config.Pipeline{{
				Uses: "test/tw/ldd-check",
			}},
		},
	}

	subpkgtlddcheckCfg := &config.Configuration{
		Package: config.Package{
			Name: "not-lddcheck",
		},
		Subpackages: []config.Subpackage{{
			Name: "also-not-lddcheck",
		}, {
			Name: "lddcheck",
			Test: &config.Test{
				Pipeline: []config.Pipeline{{
					Uses: "test/ldd-check",
				}},
			},
		}},
	}

	for _, c := range []struct {
		cfg     *config.Configuration
		dirFunc func() string
		linter  string // NB: Also used as the fallback package name for the test if unspecified!
		pass    bool
		pkgname string
	}{{
		dirFunc: t.TempDir,
		linter:  "empty",
	}, {
		dirFunc: mkfile(t, "usr/local/test.txt"),
		linter:  "usrlocal",
	}, {
		dirFunc: mkfile(t, "var/empty/test.txt"),
		linter:  "varempty",
	}, {
		dirFunc: mkfile(t, "dev/test.txt"),
		linter:  "dev",
	}, {
		dirFunc: mkfile(t, "opt/test.txt"),
		linter:  "opt",
	}, {
		dirFunc: mkfile(t, "usr/bin/object.o"),
		linter:  "object",
	}, {
		dirFunc: mkfile(t, "usr/bin/docs/README.md"),
		linter:  "documentation",
	}, {
		dirFunc: mkfile(t, "usr/lib/python3.14/site-packages/docs/test.txt"),
		linter:  "python/docs",
	}, {
		dirFunc: mkfile(t, "srv/test.txt"),
		linter:  "srv",
	}, {
		dirFunc: mkfile(t, "tmp/test.txt"),
		linter:  "tempdir",
	}, {
		dirFunc: mkfile(t, "run/test.txt"),
		linter:  "tempdir",
	}, {
		dirFunc: mkfile(t, "var/tmp/test.txt"),
		linter:  "tempdir",
	}, {
		dirFunc: mkfile(t, "var/run/test.txt"),
		linter:  "tempdir",
	}, {
		dirFunc: mkfile(t, "usr/lib/pkgconfig/test.txt"),
		linter:  "pkgconf",
		cfg:     cfg,
	}, {
		dirFunc: mkfile(t, "usr/lib/pkgconfig/test.txt"),
		linter:  "pkgconf",
		cfg:     tpkgconfCfg,
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/lib/pkgconfig/test.txt"),
		linter:  "pkgconf",
		cfg:     subpkgtpkgconfCfg,
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/share/pkgconfig/test.txt"),
		linter:  "pkgconf",
		cfg:     cfg,
	}, {
		dirFunc: mkfile(t, "usr/lib/test.so.1"),
		linter:  "lddcheck",
		cfg:     cfg,
	}, {
		dirFunc: mkfile(t, "usr/lib/test.so"),
		linter:  "lddcheck",
		cfg:     tlddcheckCfg,
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/lib/test.so"),
		linter:  "lddcheck",
		cfg:     ttwlddcheckCfg,
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/lib/test.so"),
		linter:  "lddcheck",
		cfg:     subpkgtlddcheckCfg,
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/sbin/test.sh"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "sbin/test.sh"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "sbin"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "bin"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/sbin"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/sbin/wark"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "lib/libfoo.so.1"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "lib64/libfoo64.so.1"),
		linter:  "usrmerge",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/lib/libfoo64.so.1"),
		linter:  "usrmerge",
		pass:    true,
	}, {
		dirFunc: func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, filepath.Dir("/sbin")), 0o700))
			_ = os.Symlink("/sbin", "/dev/null")
			return d
		},
		linter: "usrmerge",
		pass:   true,
	}, {
		dirFunc: func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, filepath.Dir("/usr/sbin")), 0o700))
			_ = os.Symlink("/usr/sbin", "/dev/null")
			return d
		},
		linter: "usrmerge",
		pass:   true,
	}, {
		dirFunc: func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, filepath.Dir("/bin")), 0o700))
			_ = os.Symlink("/bin", "/dev/null")
			return d
		},
		linter: "usrmerge",
		pass:   true,
	}, {
		dirFunc: func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, "bin"), 0o700))
			assert.NoError(t, os.MkdirAll(filepath.Join(d, "sbin"), 0o700))
			assert.NoError(t, os.MkdirAll(filepath.Join(d, "usr/sbin"), 0o700))
			fmt.Printf("Creating dirs and such\n")
			f, err := os.Create(filepath.Join(d, "bin/test"))
			assert.NoError(t, err)
			fmt.Fprintln(f, "blah")
			defer f.Close()

			g, err := os.Create(filepath.Join(d, "sbin/test"))
			assert.NoError(t, err)
			fmt.Fprintln(g, "blah")
			defer g.Close()

			h, err := os.Create(filepath.Join(d, "usr/sbin/test"))
			assert.NoError(t, err)
			fmt.Fprintln(h, "blah")
			defer h.Close()

			return d
		},
		linter: "usrmerge",
		pass:   false,
	}, {
		dirFunc: mkfile(t, "usr/local/lib64/stubs/libcuda.so"),
		linter:  "cudaruntimelib",
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/lib/libnvidia-ml.so"),
		linter:  "cudaruntimelib",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/lib/libcuda.so.560.35.05"),
		linter:  "cudaruntimelib",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/man/man1/foo.1"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/man/man1/foo.1"),
		linter:  "maninfo",
		pkgname: "regular-doc",
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/share/man/man8/bar.8.gz"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/local/share/man/man3/baz.3"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/man/man5/qux.5"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/info/test.info"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/info/test.info.gz"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/info/test.info-1"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/info/dir"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/share/info/test.info"),
		linter:  "maninfo",
		pkgname: "regular-doc",
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/bin/normal"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    true,
	}, {
		dirFunc: mkfile(t, "usr/local/share/info/test.info"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    false,
	}, {
		dirFunc: mkfile(t, "usr/lib/libfoo.so.1"),
		linter:  "maninfo",
		pkgname: "regular-package",
		pass:    true,
	}} {
		ctx := slogtest.Context(t)
		t.Run(c.linter, func(t *testing.T) {
			dir := c.dirFunc()
			fsys := apkofs.DirFS(ctx, dir)

			pkgname := c.pkgname
			if pkgname == "" {
				pkgname = c.linter // Fallback to using the linter name as the fake package name
			}

			// In required mode, it should raise an error.
			err := LintBuild(ctx, c.cfg, pkgname, []string{c.linter}, nil, fsys)
			if c.pass {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}

			// In warn mode, it should never raise an error.
			assert.NoError(t, LintBuild(ctx, c.cfg, pkgname, nil, []string{c.linter}, fsys))
		})
	}
}

func Test_pythonMultiplePackagesLinter(t *testing.T) {
	ctx := slogtest.Context(t)
	dir := t.TempDir()
	fsys := apkofs.DirFS(ctx, dir)

	linters := []string{"python/multiple"}

	// Base dir
	pythonPathdir := filepath.Join("usr", "lib", "python3.14", "site-packages")

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	assert.NoError(t, fsys.MkdirAll(packagedir, 0o700))

	// One package should not trip it
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// Egg info files should not count
	_, err := fsys.Create(filepath.Join(pythonPathdir, "fooegg-0.1-py3.14.egg-info"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// dist info files should not count
	_, err = fsys.Create(filepath.Join(pythonPathdir, "foodist-0.1-py3.14.dist-info"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// pth files should not count
	_, err = fsys.Create(filepath.Join(pythonPathdir, "foopth-0.1-py3.14.pth"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// .so files duplicate with a dir should not count
	_, err = fsys.Create(filepath.Join(pythonPathdir, "foo.so"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// __pycache__ dirs should not count
	err = fsys.MkdirAll(filepath.Join(pythonPathdir, "__pycache__"), 0o700)
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))

	// Make another "package" (at this point we should have 2)
	packagedir = filepath.Join(pythonPathdir, "bar")
	err = fsys.MkdirAll(packagedir, 0o700)
	assert.NoError(t, err)

	// Two should trip it
	assert.Error(t, LintBuild(ctx, nil, "multiple", linters, nil, fsys))
}

func Test_pythonTestLinter(t *testing.T) {
	ctx := slogtest.Context(t)

	dir := t.TempDir()
	fsys := apkofs.DirFS(ctx, dir)

	linters := []string{"python/test"}

	// Base dir
	pythonPathdir := filepath.Join("usr", "lib", "python3.14", "site-packages")

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	assert.NoError(t, fsys.MkdirAll(packagedir, 0o700))

	// One package should not trip it
	assert.NoError(t, LintBuild(ctx, nil, "python-test", linters, nil, fsys))

	// Create docs
	docsdir := filepath.Join(pythonPathdir, "test")
	assert.NoError(t, fsys.MkdirAll(docsdir, 0o700))

	// This should trip
	assert.Error(t, LintBuild(ctx, nil, "python-test", linters, nil, fsys))
}

func Test_setUidGidLinter(t *testing.T) {
	ctx := slogtest.Context(t)
	dir := t.TempDir()
	fsys := apkofs.DirFS(ctx, dir)

	linters := []string{"setuidgid"}
	filePath := filepath.Join("test.txt")

	_, err := fsys.Create(filePath)
	assert.NoError(t, err)
	assert.NoError(t, fsys.Chmod(filePath, 0o770|fs.ModeSetuid|fs.ModeSetgid))
	assert.Error(t, LintBuild(ctx, nil, "setuidgid", linters, nil, fsys))
}

func Test_worldWriteLinter(t *testing.T) {
	ctx := slogtest.Context(t)

	linters := []string{"worldwrite"}

	dir := t.TempDir()
	fsys := apkofs.DirFS(ctx, dir)
	assert.NoError(t, fsys.MkdirAll(filepath.Join("usr", "lib"), 0o777))

	// Ensure 777 dirs don't trigger it
	assert.NoError(t, LintBuild(ctx, nil, "worldwrite", linters, nil, fsys))

	// Create test file
	filePath := filepath.Join("usr", "lib", "test.txt")
	_, err := fsys.Create(filePath)
	assert.NoError(t, err)

	// Set writeable and executable bits for non-world
	err = fsys.Chmod(filePath, 0o770)
	assert.NoError(t, err)

	// Linter should not trigger
	assert.NoError(t, LintBuild(ctx, nil, "worldwrite", linters, nil, fsys))

	// Set writeable bit (but not executable bit)
	err = fsys.Chmod(filePath, 0o776)
	assert.NoError(t, err)

	// Linter should trigger
	assert.Error(t, LintBuild(ctx, nil, "worldwrite", linters, nil, fsys))

	// Set writeable and executable bit
	err = fsys.Chmod(filePath, 0o777)
	assert.NoError(t, err)

	// Linter should trigger
	assert.Error(t, LintBuild(ctx, nil, "worldwrite", linters, nil, fsys))
}

func Test_lintApk(t *testing.T) {
	ctx := slogtest.Context(t)

	assert.NoError(t, LintAPK(ctx, filepath.Join("testdata", "hello-wolfi-2.12.1-r1.apk"), DefaultRequiredLinters(), DefaultWarnLinters()))
	assert.NoError(t, LintAPK(ctx, filepath.Join("testdata", "kubeflow-pipelines-2.1.3-r7.apk"), DefaultRequiredLinters(), DefaultWarnLinters()))
}
