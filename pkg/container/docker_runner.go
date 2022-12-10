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
	"fmt"
	"log"

	"github.com/docker/docker/client"
)

type DKRunner struct {
	Runner
}

// DockerRunner returns a Docker Runner implementation.
func DockerRunner() Runner {
	return &DKRunner{}
}

// Run runs a Docker task given a Config and command string.
func (dk *DKRunner) Run(cfg Config, args ...string) error {
	return fmt.Errorf("Run not implemented")
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
