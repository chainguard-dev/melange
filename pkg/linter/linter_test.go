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

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/stretchr/testify/assert"
)

func TestLinters(t *testing.T) {
	mkfile := func(t *testing.T, path string) func() string {
		return func() string {
			d := t.TempDir()
			assert.NoError(t, os.MkdirAll(filepath.Join(d, filepath.Dir(path)), 0700))
			f, err := os.Create(filepath.Join(d, path))
			assert.NoError(t, err)
			fmt.Fprintln(f, "blah")
			defer f.Close()
			return d
		}
	}

	for _, c := range []struct {
		dirFunc func() string
		linter  string
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
	}} {
		ctx := slogtest.TestContextWithLogger(t)
		t.Run(c.linter, func(t *testing.T) {
			dir := c.dirFunc()
			// In required mode, it should raise an error.
			assert.Error(t, LintBuild(ctx, c.linter, dir, []string{c.linter}, nil))

			// In warn mode, it should never raise an error.
			assert.NoError(t, LintBuild(ctx, c.linter, dir, nil, []string{c.linter}))
		})
	}
}

func Test_pythonMultiplePackagesLinter(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)
	dir := t.TempDir()

	linters := []string{"python/multiple"}

	// Base dir
	pythonPathdir := filepath.Join(dir, "usr", "lib", "python3.14", "site-packages")

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	assert.NoError(t, os.MkdirAll(packagedir, 0700))

	// One package should not trip it
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// Egg info files should not count
	_, err := os.Create(filepath.Join(pythonPathdir, "fooegg-0.1-py3.14.egg-info"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// dist info files should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foodist-0.1-py3.14.dist-info"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// pth files should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foopth-0.1-py3.14.pth"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// .so files duplicate with a dir should not count
	_, err = os.Create(filepath.Join(pythonPathdir, "foo.so"))
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// __pycache__ dirs should not count
	err = os.MkdirAll(filepath.Join(pythonPathdir, "__pycache__"), 0700)
	assert.NoError(t, err)
	assert.NoError(t, LintBuild(ctx, "multiple", dir, linters, nil))

	// Make another "package" (at this point we should have 2)
	packagedir = filepath.Join(pythonPathdir, "bar")
	err = os.MkdirAll(packagedir, 0700)
	assert.NoError(t, err)

	// Two should trip it
	assert.Error(t, LintBuild(ctx, "multiple", dir, linters, nil))
}

func Test_pythonTestLinter(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)

	dir := t.TempDir()

	linters := []string{"python/test"}

	// Base dir
	pythonPathdir := filepath.Join(dir, "usr", "lib", "python3.14", "site-packages")

	// Make one "package"
	packagedir := filepath.Join(pythonPathdir, "foo")
	assert.NoError(t, os.MkdirAll(packagedir, 0700))

	// One package should not trip it
	assert.NoError(t, LintBuild(ctx, "python-test", dir, linters, nil))

	// Create docs
	docsdir := filepath.Join(pythonPathdir, "test")
	assert.NoError(t, os.MkdirAll(docsdir, 0700))

	// This should trip
	assert.Error(t, LintBuild(ctx, "python-test", dir, linters, nil))
}

func Test_setUidGidLinter(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)

	linters := []string{"setuidgid"}
	filePath := filepath.Join(t.TempDir(), "test.txt")

	f, err := os.Create(filePath)
	assert.NoError(t, err)
	assert.NoError(t, f.Close())
	assert.NoError(t, os.Chmod(filePath, 0770|fs.ModeSetuid|fs.ModeSetgid))
	assert.NoError(t, LintBuild(ctx, "setuidgid", t.TempDir(), linters, nil))
}

func Test_worldWriteLinter(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)

	linters := []string{"worldwrite"}

	dir := t.TempDir()
	assert.NoError(t, os.MkdirAll(filepath.Join(dir, "usr", "lib"), 0777))

	// Ensure 777 dirs don't trigger it
	assert.NoError(t, LintBuild(ctx, "worldwrite", dir, linters, nil))

	// Create test file
	filePath := filepath.Join(dir, "usr", "lib", "test.txt")
	_, err := os.Create(filePath)
	assert.NoError(t, err)

	// Set writeable and executable bits for non-world
	err = os.Chmod(filePath, 0770)
	assert.NoError(t, err)

	// Linter should not trigger
	assert.NoError(t, LintBuild(ctx, "worldwrite", dir, linters, nil))

	// Set writeable bit (but not executable bit)
	err = os.Chmod(filePath, 0776)
	assert.NoError(t, err)

	// Linter should trigger
	assert.Error(t, LintBuild(ctx, "worldwrite", dir, linters, nil))

	// Set writeable and executable bit
	err = os.Chmod(filePath, 0777)
	assert.NoError(t, err)

	// Linter should trigger
	assert.Error(t, LintBuild(ctx, "worldwrite", dir, linters, nil))
}

func Test_lintApk(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)

	assert.NoError(t, LintAPK(ctx, filepath.Join("testdata", "hello-wolfi-2.12.1-r1.apk"), DefaultRequiredLinters(), DefaultWarnLinters()))
	assert.NoError(t, LintAPK(ctx, filepath.Join("testdata", "kubeflow-pipelines-2.1.3-r7.apk"), DefaultRequiredLinters(), DefaultWarnLinters()))
}
