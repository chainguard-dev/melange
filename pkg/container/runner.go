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

type Runner interface {
	Run(cfg Config, cmd ...string) error
}

// GetRunner returns the preferred runner implementation for the
// given environment.
func GetRunner() Runner {
	return BubblewrapRunner()
}

// MonitorCmd sets up the stdout/stderr pipes and then supervises
// execution of an exec.Cmd.
func MonitorCmd(cfg Config, cmd *exec.Cmd) error {
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

	go MonitorPipe(cfg.Logger, stdout, finishStdout)
	go MonitorPipe(cfg.Logger, stderr, finishStderr)

	if err := cmd.Wait(); err != nil {
		return err
	}

	<-finishStdout
	<-finishStderr

	return nil
}
