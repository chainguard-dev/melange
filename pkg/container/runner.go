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

package container

import (
	"context"
	"fmt"
	"io"
	"os/exec"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type Runner interface {
	Name() string
	TestUsability(ctx context.Context) bool
	// OCIImageLoader returns a Loader that will load an OCI image from a stream.
	// It should return the Loader, which will be used to load the provided image
	// as a tar stream into the Loader. That image will be used as the root when StartPod() the container.
	OCIImageLoader() Loader
	StartPod(ctx context.Context, cfg *Config) error
	Run(ctx context.Context, cfg *Config, cmd ...string) error
	TerminatePod(ctx context.Context, cfg *Config) error
	// TempDir returns the base for temporary directory, or "" if whatever is provided by the system is fine
	TempDir() string
	// WorkspaceTar returns an io.ReadCloser that can be used to read the status of the workspace.
	// The io.ReadCloser itself is a tar stream, which can be written to an io.Writer as is,
	// or passed to an fs.FS processor
	WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error)
}

type Loader interface {
	LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error)
}

// GetRunner returns the requested runner implementation.
func GetRunner(ctx context.Context, s string, log log.Logger) (Runner, error) {
	switch s {
	case BubblewrapName:
		return BubblewrapRunner(log), nil
	case DockerName:
		return DockerRunner(log), nil
	case LimaName:
		return LimaRunner(ctx, log)
	case KubernetesName:
		return KubernetesRunner(ctx, log)
	case DaggerName:
		return DaggerRunner(ctx, log)
	}
	return nil, fmt.Errorf("unknown virtualizer %q", s)
}

// monitorCmd sets up the stdout/stderr pipes and then supervises
// execution of an exec.Cmd.
func monitorCmd(cfg *Config, cmd *exec.Cmd) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	finishStdout := make(chan struct{})
	finishStderr := make(chan struct{})

	go monitorPipe(cfg.Logger, log.InfoLevel, stdout, finishStdout)
	go monitorPipe(cfg.Logger, log.WarnLevel, stderr, finishStderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	<-finishStdout
	<-finishStderr

	return nil
}
