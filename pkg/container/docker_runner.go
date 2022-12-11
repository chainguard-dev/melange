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
	_ "os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	_ "github.com/docker/docker/pkg/stdcopy"
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

	ctx := context.Background()
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: cfg.ImgDigest,
		Cmd: []string{"/bin/sh", "-c", "while true; do sleep 5; done"},
		Tty: false,
	}, nil, nil, nil, "")
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

	return nil
}

// Run runs a Docker task given a Config and command string.
func (dk *DKRunner) Run(cfg *Config, args ...string) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

//	stdoutPipeR, stdoutPipeW, err := os.Pipe()
//	if err != nil {
//		return err
//	}

//	stderrPipeR, stderrPipeW, err := os.Pipe()
//	if err != nil {
//		return err
//	}

//	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{
//		ShowStdout: true,
//		ShowStderr: true,
//	})

//	finishStdout := make(chan struct{})
//	finishStderr := make(chan struct{})

//	go monitorPipe(cfg.Logger, stdoutPipeR, finishStdout)
//	go monitorPipe(cfg.Logger, stderrPipeR, finishStderr)
//	stdcopy.StdCopy(stdoutPipeW, stderrPipeW, out)

//	<-finishStdout
//	<-finishStderr

	return nil
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

	return true
}

// NeedsImage determines whether an image is needed for the
// given runner method.  For Docker, this is true.
func (dk *DKRunner) NeedsImage() bool {
	return true
}
