// Copyright 2024 Chainguard, Inc.
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

package container

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"path"
)

// parallelBuildDirPrefix is the path prefix (inside the runner's build
// environment) under which each parallel subpackage's isolated filesystem view
// is constructed, e.g. /tmp/parallel-build-<id>.
const parallelBuildDirPrefix = "/tmp/parallel-build-"

// melangeOutDirName is the directory (under the workspace) where (sub)package
// outputs are staged. It mirrors build.melangeOutputDirName.
const melangeOutDirName = "melange-out"

// Isolation describes a per-invocation isolated filesystem view requested for a
// parallel subpackage build. When Config.Isolation is non-nil, a Runner that
// implements IsolatedRunner executes commands inside this isolated view:
//
//   - /home/build is an overlay whose upper layer is a private tmpfs, so writes
//     do not persist for or leak to other subpackages.
//   - /home/build/melange-out is a read-only view of the shared outputs as they
//     stood at batch start (the main package plus any earlier-batch subpackages).
//   - /home/build/melange-out/<SubpkgName> is a read-write bind whose contents
//     are copied back into the shared workspace once the batch completes.
type Isolation struct {
	// ID is unique per parallel subpackage; it namespaces the isolation tree.
	ID string
	// SubpkgName is the subpackage being built; melange-out/<SubpkgName> is the
	// read-write target that is copied back after the batch completes.
	SubpkgName string
}

// BaseDir returns the root of the isolation tree, e.g. /tmp/parallel-build-<id>.
func (i *Isolation) BaseDir() string {
	return parallelBuildDirPrefix + i.ID
}

// ChrootDir returns the directory the build chroots into.
func (i *Isolation) ChrootDir() string {
	return path.Join(i.BaseDir(), "root")
}

// OutDir returns the private read-write output directory whose contents are
// copied back into melange-out/<SubpkgName> after the batch completes.
func (i *Isolation) OutDir() string {
	return path.Join(i.BaseDir(), "out")
}

// IsolatedRunner is implemented by Runners that support per-subpackage build
// isolation (see Isolation). The build layer type-asserts a Runner to this
// interface before scheduling a parallel batch; Runners that do not implement
// it cannot run parallel subpackages.
type IsolatedRunner interface {
	// SetupIsolation constructs the isolated filesystem view described by
	// cfg.Isolation.
	SetupIsolation(ctx context.Context, cfg *Config) error
	// CopyOutIsolation copies the isolated outputs back into the shared
	// melange-out/<SubpkgName>. It is only called for subpackages that built
	// successfully.
	CopyOutIsolation(ctx context.Context, cfg *Config) error
	// TeardownIsolation unmounts and removes the isolated filesystem view. It is
	// always called, even when the build failed, and should be tolerant of a
	// partially-constructed view.
	TeardownIsolation(ctx context.Context, cfg *Config) error
}

// NewIsolationID returns a random hex identifier for an isolation tree.
func NewIsolationID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
