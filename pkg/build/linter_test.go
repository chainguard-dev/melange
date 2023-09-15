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

package build

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"chainguard.dev/melange/pkg/config"
)

func Test_usrLocalLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "test",
			Version: "4.2.0",
			Epoch:   0,
			Checks: config.Checks{
				Enabled:  []string{"usrlocal"},
				Disabled: []string{"setuidgid"},
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
	lctx := LinterContext{cfg.Package.Name, &cfg, &cfg.Package.Checks}
	assert.Error(t, lintPackageFs(lctx, fsys, linters))
}

func Test_setUidGidLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "test",
			Version: "4.2.0",
			Epoch:   0,
			Checks: config.Checks{
				Enabled:  []string{"setuidgid"},
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

	err = os.Chmod(filePath, 0770|fs.ModeSetuid|fs.ModeSetgid)
	assert.NoError(t, err)

	linters := cfg.Package.Checks.GetLinters()
	assert.Equal(t, linters, []string{"setuidgid"})
	fsys := os.DirFS(dir)
	lctx := LinterContext{cfg.Package.Name, &cfg, &cfg.Package.Checks}
	assert.Error(t, lintPackageFs(lctx, fsys, linters))
}

func Test_disableDefaultLinter(t *testing.T) {
	dir, err := os.MkdirTemp("", "melange.XXXXX")
	defer os.RemoveAll(dir)
	assert.NoError(t, err)

	cfg := config.Configuration{
		Package: config.Package{
			Name:    "test",
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
	lctx := LinterContext{cfg.Package.Name, &cfg, &cfg.Package.Checks}
	assert.NoError(t, lintPackageFs(lctx, fsys, linters))
}
