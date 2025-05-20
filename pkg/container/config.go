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
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"golang.org/x/crypto/ssh"
)

const (
	runnerWorkdir = "/home/build"
)

const (
	// DefaultWorkspaceDir is the default path to the workspace directory in the runner's environment.
	DefaultWorkspaceDir = "/home/build"
	// DefaultCacheDir is the default path to the cache directory in the runner's environment.
	DefaultCacheDir = "/var/cache/melange"
	// DefaultResolvConfPath is the default path to the resolv.conf file in the runner's environment.
	DefaultResolvConfPath = "/etc/resolv.conf"
)

type BindMount struct {
	Source      string
	Destination string
}

type Capabilities struct {
	Networking bool
	Add        []string // List of kernel capabilities to add to the container.
	Drop       []string // List of kernel capabilities to drop from the container.
}

type Config struct {
	PackageName           string
	Mounts                []BindMount
	Capabilities          Capabilities
	Environment           map[string]string
	ImgRef                string
	PodID                 string
	Arch                  apko_types.Architecture
	RunAsUID              string
	RunAs                 string
	WorkspaceDir          string
	CPU, CPUModel, Memory string
	SSHKey                ssh.Signer
	SSHAddress            string
	SSHWorkspaceAddress   string
	SSHHostKey            string
	Disk                  string
	Timeout               time.Duration
}
