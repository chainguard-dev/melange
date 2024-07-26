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
}

type Config struct {
	PackageName  string
	Mounts       []BindMount
	Capabilities Capabilities
	Environment  map[string]string
	ImgRef       string
	PodID        string
	Arch         apko_types.Architecture
	RunAs        string
	WorkspaceDir string
	CPU, Memory  string
	SSHKey       []byte
	SSHPort      string
	Disk         string
	Timeout      time.Duration
}
