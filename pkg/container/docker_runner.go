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
	"os"

	"chainguard.dev/apko/pkg/log"
	"go.opentelemetry.io/otel"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	image_spec "github.com/opencontainers/image-spec/specs-go/v1"
)

const DockerName = "docker"

// docker is a Runner implementation that uses the docker library.
type docker struct {
	logger log.Logger
}

// DockerRunner returns a Docker Runner implementation.
func DockerRunner(logger log.Logger) Runner {
	return &docker{logger}
}

func (dk *docker) Name() string {
	return DockerName
}

// StartPod starts a pod for supporting a Docker task, if
// necessary.
func (dk *docker) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.StartPod")
	defer span.End()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	mounts := []mount.Mount{}
	for _, bind := range cfg.Mounts {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: bind.Source,
			Target: bind.Destination,
		})
	}

	hostConfig := &container.HostConfig{
		Mounts: mounts,
	}

	platform := &image_spec.Platform{
		Architecture: cfg.Arch.String(),
		OS:           "linux",
	}

	// ldconfig is run to prime ld.so.cache for glibc packages which require it.
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: cfg.ImgRef,
		Cmd:   []string{"/bin/sh", "-c", "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true\nwhile true; do sleep 5; done"},
		Tty:   false,
	}, hostConfig, nil, platform, "")
	if err != nil {
		return err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	cfg.PodID = resp.ID
	cfg.Logger.Printf("pod %s started.", cfg.PodID)

	return nil
}

// TerminatePod terminates a pod for supporting a Docker task,
// if necessary.
func (dk *docker) TerminatePod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.TerminatePod")
	defer span.End()

	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	if err := cli.ContainerRemove(ctx, cfg.PodID, types.ContainerRemoveOptions{
		Force: true,
	}); err != nil {
		return err
	}

	cfg.Logger.Printf("pod %s terminated.", cfg.PodID)

	return nil
}

// TestUsability determines if the Docker runner can be used
// as a container runner.
func (dk *docker) TestUsability(ctx context.Context) bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		dk.logger.Printf("cannot use docker for containers: %v", err)
		return false
	}
	defer cli.Close()

	_, err = cli.Ping(ctx)
	if err != nil {
		dk.logger.Printf("cannot use docker for containers: %v", err)
		return false
	}

	return true
}

// OCIImageLoader create a loader to load an OCI image into the docker daemon.
func (dk *docker) OCIImageLoader() Loader {
	return &dockerLoader{}
}

// TempDir returns the base for temporary directory. For docker
// this is whatever the system provides.
func (dk *docker) TempDir() string {
	return ""
}

// waitForCommand waits for a command to complete in the pod.
func (dk *docker) waitForCommand(cfg *Config, ctx context.Context, attachResp types.HijackedResponse, taskIDResp types.IDResponse) error {
	stdoutPipeR, stdoutPipeW, err := os.Pipe()
	if err != nil {
		return err
	}

	stderrPipeR, stderrPipeW, err := os.Pipe()
	if err != nil {
		return err
	}

	finishStdout := make(chan struct{})
	finishStderr := make(chan struct{})

	go monitorPipe(cfg.Logger, log.InfoLevel, stdoutPipeR, finishStdout)
	go monitorPipe(cfg.Logger, log.WarnLevel, stderrPipeR, finishStderr)
	_, err = stdcopy.StdCopy(stdoutPipeW, stderrPipeW, attachResp.Reader)

	stdoutPipeW.Close()
	stderrPipeW.Close()

	<-finishStdout
	<-finishStderr

	return err
}

// Run runs a Docker task given a Config and command string.
// The resultant filesystem can be read from the io.ReadCloser
func (dk *docker) Run(ctx context.Context, cfg *Config, args ...string) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	environ := []string{}
	for k, v := range cfg.Environment {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// TODO(kaniini): We want to use the build user here, but for now lets keep
	// it simple.
	taskIDResp, err := cli.ContainerExecCreate(ctx, cfg.PodID, types.ExecConfig{
		User:         "build",
		Cmd:          args,
		WorkingDir:   runnerWorkdir,
		Env:          environ,
		Tty:          false,
		AttachStderr: true,
		AttachStdout: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create exec task inside pod: %w", err)
	}

	attachResp, err := cli.ContainerExecAttach(ctx, taskIDResp.ID, types.ExecStartCheck{
		Tty: false,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to exec task: %w", err)
	}

	if err := dk.waitForCommand(cfg, ctx, attachResp, taskIDResp); err != nil {
		return err
	}

	inspectResp, err := cli.ContainerExecInspect(ctx, taskIDResp.ID)
	if err != nil {
		return fmt.Errorf("failed to get exit code from task: %w", err)
	}

	switch inspectResp.ExitCode {
	case 0:
		return nil
	default:
		return fmt.Errorf("task exited with code %d", inspectResp.ExitCode)
	}
}

// WorkspaceTar implements Runner
// This is a noop for Docker, which uses bind-mounts to manage the workspace
func (dk *docker) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	return nil, nil
}

type dockerLoader struct{}

func (d dockerLoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (string, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.LoadImage")
	defer span.End()

	creationTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return "", err
	}

	img, err := apko_oci.BuildImageFromLayer(layer, bc.ImageConfiguration(), creationTime, arch, bc.Logger())
	if err != nil {
		return "", err
	}

	ref, err := apko_oci.LoadImage(ctx, img, bc.Logger(), []string{"melange:latest"})
	if err != nil {
		return "", err
	}
	return ref.String(), nil
}
