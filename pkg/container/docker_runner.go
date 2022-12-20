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
	"log"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

type DKRunner struct {
	Runner
}

// DockerRunner returns a Docker Runner implementation.
func DockerRunner() Runner {
	return &DKRunner{}
}

// StartPod starts a pod for supporting a Docker task, if
// necessary.
func (dk *DKRunner) StartPod(cfg *Config) error {
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

	ctx := context.Background()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: cfg.ImgDigest,
		Cmd:   []string{"/bin/sh", "-c", "while true; do sleep 5; done"},
		Tty:   false,
	}, hostConfig, nil, nil, "")
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
func (dk *DKRunner) TerminatePod(cfg *Config) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	ctx := context.Background()
	if err := cli.ContainerRemove(ctx, cfg.PodID, types.ContainerRemoveOptions{
		Force: true,
	}); err != nil {
		return err
	}

	cfg.Logger.Printf("pod %s terminated.", cfg.PodID)

	return nil
}

// Run runs a Docker task given a Config and command string.
func (dk *DKRunner) Run(cfg *Config, args ...string) error {
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

	ctx := context.Background()

	// TODO(kaniini): We want to use the build user here, but for now lets keep
	// it simple.
	taskIDResp, err := cli.ContainerExecCreate(ctx, cfg.PodID, types.ExecConfig{
		User:         "build",
		Cmd:          args,
		WorkingDir:   "/home/build",
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

// TestUsability determines if the Docker runner can be used
// as a container runner.
func (dk *DKRunner) TestUsability() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("cannot use docker for containers: %v", err)
		return false
	}
	defer cli.Close()

	_, err = cli.Ping(context.Background())
	if err != nil {
		log.Printf("cannot use docker for containers: %v", err)
		return false
	}

	return true
}

// NeedsImage determines whether an image is needed for the
// given runner method.  For Docker, this is true.
func (dk *DKRunner) NeedsImage() bool {
	return true
}

// waitForCommand waits for a command to complete in the pod.
func (dk *DKRunner) waitForCommand(cfg *Config, ctx context.Context, attachResp types.HijackedResponse, taskIDResp types.IDResponse) error {
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

	go monitorPipe(cfg.Logger, stdoutPipeR, finishStdout)
	go monitorPipe(cfg.Logger, stderrPipeR, finishStderr)
	_, err = stdcopy.StdCopy(stdoutPipeW, stderrPipeW, attachResp.Reader)

	stdoutPipeW.Close()
	stderrPipeW.Close()

	<-finishStdout
	<-finishStderr

	return err
}
