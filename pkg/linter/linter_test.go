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
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/config"
	linter_defaults "chainguard.dev/melange/pkg/linter/defaults"
)

func checksOnly(onlyLint string) config.Checks {
	checksDisabled := []string{}
	for _, lint := range linter_defaults.GetDefaultLinters(linter_defaults.LintersBuild) {
		if lint != onlyLint {
			checksDisabled = append(checksDisabled, lint)
		}
	}
	return config.Checks{
		Enabled:  []string{onlyLint},
		Disabled: checksDisabled,
	}
}

func Test_emptyLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testempty",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("empty"),
		},
	}

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"empty"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_usrLocalLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testusrlocal",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("usrlocal"),
		},
	}

	err = os.MkdirAll(filepath.Join(dir, "usr", "local"), 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(dir, "usr", "local", "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"usrlocal"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_varEmptyLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testvarempty",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("varempty"),
		},
	}

	pathdir := filepath.Join(dir, "var", "empty")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(pathdir, "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"varempty"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_devLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testdev",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("dev"),
		},
	}

	pathdir := filepath.Join(dir, "dev")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(pathdir, "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"dev"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_optLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testopt",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("opt"),
		},
	}

	pathdir := filepath.Join(dir, "opt")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(pathdir, "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"opt"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_pythonDocsLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testpythondocs",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("python/docs"),
		},
	}

	// Base dir
	pythonPathdir := filepath.Join(dir, "usr", "lib", "python3.14", "site-packages")

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"python/docs"})

	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	err = os.MkdirAll(packagedir, 0700)
	assert.NoError(t, err)

	// One package should not trip it
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Create docs
	docsdir := filepath.Join(pythonPathdir, "docs")
	err = os.MkdirAll(docsdir, 0700)
	assert.NoError(t, err)

	// This should trip
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_pythonMultiplePackagesLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testpythonmultiplepackages",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("python/multiple"),
		},
	}

	// Base dir
	pythonPathdir := filepath.Join(dir, "usr", "lib", "python3.14", "site-packages")

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"python/multiple"})

	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	err = os.MkdirAll(packagedir, 0700)
	assert.NoError(t, err)

	// One package should not trip it
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Egg info files should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "fooegg-0.1-py3.14.egg-info"))
	assert.NoError(t, err)
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// dist info files should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foodist-0.1-py3.14.dist-info"))
	assert.NoError(t, err)
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// pth files should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foopth-0.1-py3.14.pth"))
	assert.NoError(t, err)
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// .so files duplicate with a dir should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foo.so"))
	assert.NoError(t, err)
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// __pycache__ dirs should not count
	err = os.MkdirAll(filepath.Join(pythonPathdir, "__pycache__"), 0700)
	assert.NoError(t, err)
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Make another "package" (at this point we should have 2)
	packagedir = filepath.Join(pythonPathdir, "bar")
	err = os.MkdirAll(packagedir, 0700)
	assert.NoError(t, err)

	// Two should trip it
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_pythonTestLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testpythontest",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("python/test"),
		},
	}

	// Base dir
	pythonPathdir := filepath.Join(dir, "usr", "lib", "python3.14", "site-packages")

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"python/test"})

	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	err = os.MkdirAll(packagedir, 0700)
	assert.NoError(t, err)

	// One package should not trip it
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Create docs
	docsdir := filepath.Join(pythonPathdir, "test")
	err = os.MkdirAll(docsdir, 0700)
	assert.NoError(t, err)

	// This should trip
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_srvLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testsrv",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("srv"),
		},
	}

	pathdir := filepath.Join(dir, "srv")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(pathdir, "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"srv"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_tempDirLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testtempdir",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("tempdir"),
		},
	}

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"tempdir"})

	fsys := os.DirFS(dir)

	// Test /tmp check
	pathdir := filepath.Join(dir, "tmp")
	filename := filepath.Join(pathdir, "test.txt")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filename)
	assert.NoError(t, err)
	os.Remove(filename)

	// Test /run check
	pathdir = filepath.Join(dir, "run")
	filename = filepath.Join(pathdir, "test.txt")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filename)
	assert.NoError(t, err)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
	os.Remove(filename)

	// Test /var/tmp check
	pathdir = filepath.Join(dir, "var", "tmp")
	filename = filepath.Join(pathdir, "test.txt")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filename)
	assert.NoError(t, err)
	os.Remove(filename)

	// Test /var/run check
	pathdir = filepath.Join(dir, "var", "run")
	filename = filepath.Join(pathdir, "test.txt")
	err = os.MkdirAll(pathdir, 0700)
	assert.NoError(t, err)
	_, err = os.Create(filename)
	assert.NoError(t, err)
	os.Remove(filename)
}

func Test_setUidGidLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testsetuidgid",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("setuidgid"),
		},
	}

	usrLocalDirPath := filepath.Join(dir, "usr", "local")
	filePath := filepath.Join(usrLocalDirPath, "test.txt")

	err = os.MkdirAll(usrLocalDirPath, 0770)
	assert.NoError(t, err)

	_, err = os.Create(filepath.Join(filePath))
	assert.NoError(t, err)

	err = os.Chmod(filePath, 0770|fs.ModeSetuid|fs.ModeSetgid)
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"setuidgid"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_worldWriteLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testworldwrite",
			Version: "4.2.0",
			Epoch:   0,
			Checks:  checksOnly("worldwrite"),
		},
	}

	usrLocalDirPath := filepath.Join(dir, "usr", "lib")
	err = os.MkdirAll(usrLocalDirPath, 0777)
	assert.NoError(t, err)

	// Ensure 777 dirs don't trigger it
	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"worldwrite"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Create test file
	filePath := filepath.Join(usrLocalDirPath, "test.txt")
	_, err = os.Create(filepath.Join(filePath))
	assert.NoError(t, err)

	// Set writeable and executable bits for non-world
	err = os.Chmod(filePath, 0770)
	assert.NoError(t, err)

	// Linter should not trigger
	called = false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)

	// Set writeable bit (but not executable bit)
	err = os.Chmod(filePath, 0776)
	assert.NoError(t, err)

	// Linter should trigger
	called = false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)

	// Set writeable and executable bit
	err = os.Chmod(filePath, 0777)
	assert.NoError(t, err)

	// Linter should trigger
	called = false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.True(t, called)
}

func Test_disableDefaultLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testdisable",
			Version: "4.2.0",
			Epoch:   0,
			Checks: config.Checks{
				Disabled: []string{"usrlocal"},
			},
		},
	}

	usrLocalDirPath := filepath.Join(dir, "usr", "local")
	filePath := filepath.Join(usrLocalDirPath, "test.txt")

	err = os.MkdirAll(usrLocalDirPath, 0770)
	assert.NoError(t, err)

	_, err = os.Create(filepath.Join(filePath))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)
}

func Test_lintApk(t *testing.T) {
	ctx := context.Background()
	called := false
	assert.NoError(t, LintApk(ctx, filepath.Join("testdata", "hello-wolfi-2.12.1-r1.apk"), func(err error) {
		called = true
	}, linter_defaults.GetDefaultLinters(linter_defaults.LintersApk)))
	assert.False(t, called)

	assert.NoError(t, LintApk(ctx, filepath.Join("testdata", "kubeflow-pipelines-2.1.3-r7.apk"), func(err error) {
		called = true
	}, linter_defaults.GetDefaultLinters(linter_defaults.LintersApk)))
	assert.True(t, called)
}
