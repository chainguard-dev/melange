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
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/config"
)

func Test_emptyLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "testempty",
			Version: "4.2.0",
			Epoch:   0,
			Checks: config.Checks{
				Enabled:  []string{"empty"},
				Disabled: []string{"dev", "opt", "setuidgid", "srv", "strip", "tempdir", "usrlocal", "varempty", "worldwrite"},
			},
		},
	}

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"empty"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"usrlocal"},
				Disabled: []string{"dev", "empty", "opt", "setuidgid", "strip", "srv", "tempdir", "varempty", "worldwrite"},
			},
		},
	}

	err = os.MkdirAll(filepath.Join(dir, "usr", "local"), 0700)
	assert.NoError(t, err)
	_, err = os.Create(filepath.Join(dir, "usr", "local", "test.txt"))
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"usrlocal"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"varempty"},
				Disabled: []string{"dev", "empty", "opt", "setuidgid", "strip", "srv", "tempdir", "usrlocal", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"dev"},
				Disabled: []string{"empty", "opt", "setuidgid", "strip", "srv", "tempdir", "usrlocal", "varempty", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"opt"},
				Disabled: []string{"dev", "empty", "setuidgid", "strip", "srv", "tempdir", "usrlocal", "varempty", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
	called := false
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
			Checks: config.Checks{
				Enabled:  []string{"srv"},
				Disabled: []string{"dev", "empty", "opt", "setuidgid", "strip", "tempdir", "usrlocal", "varempty", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"tempdir"},
				Disabled: []string{"dev", "empty", "opt", "setuidgid", "strip", "srv", "usrlocal", "varempty", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"setuidgid"},
				Disabled: []string{"dev", "empty", "opt", "srv", "strip", "tempdir", "usrlocal", "varempty", "worldwrite"},
			},
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
			Checks: config.Checks{
				Enabled:  []string{"worldwrite"},
				Disabled: []string{"dev", "empty", "opt", "setuidgid", "strip", "srv", "tempdir", "usrlocal", "varempty"},
			},
		},
	}

	usrLocalDirPath := filepath.Join(dir, "usr", "lib")
	err = os.MkdirAll(usrLocalDirPath, 0777)
	assert.NoError(t, err)

	// Ensure 777 dirs don't trigger it
	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"worldwrite"})
	fsys := os.DirFS(dir)
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
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
	lctx := NewLinterContext(cfg.Package.Name, fsys, &cfg, &cfg.Package.Checks)
	called := false
	assert.NoError(t, lctx.LintPackageFs(fsys, func(err error) {
		called = true
	}, linters))
	assert.False(t, called)
}
