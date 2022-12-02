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
	"os/exec"
)

type BWRunner struct {
	Runner
}

// BubblewrapRunner returns a Bubblewrap Runner implementation.
func BubblewrapRunner() Runner {
	return &BWRunner{}
}

// Run runs a Bubblewrap task given a Config and command string.
func (bw *BWRunner) Run(cfg Config, args ...string) error {
	baseargs := []string{}

	for _, bind := range cfg.Mounts {
		baseargs = append(baseargs, "--bind", bind.Source, bind.Destination)
	}

	baseargs = append(baseargs, "--unshare-pid",
		"--dev", "/dev",
		"--proc", "/proc",
		"--chdir", "/home/build",
		"--clearenv")

	if !cfg.Capabilities.Networking {
		baseargs = append(baseargs, "--unshare-net")
	}

	for k, v := range cfg.Environment {
		baseargs = append(baseargs, "--setenv", k, v)
	}

	args = append(baseargs, args...)
	execCmd := exec.Command("bwrap", args...)

	return monitorCmd(cfg, execCmd)
}
