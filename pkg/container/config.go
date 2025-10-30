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
	"crypto/ed25519"
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
	PackageName              string
	Mounts                   []BindMount
	Capabilities             Capabilities
	Environment              map[string]string
	ImgRef                   string
	PodID                    string
	Arch                     apko_types.Architecture
	RunAsUID                 string
	RunAs                    string
	WorkspaceDir             string
	CacheDir                 string
	CPU, CPUModel, Memory    string
	SSHKey                   ssh.Signer
	SSHAddress               string             // SSH address for the build / chrooted environment
	SSHControlAddress        string             // SSH address for the control / management environment
	SSHHostKey               string             // Path to known_hosts file containing the VM's host key
	VMHostKeySigner          ssh.Signer         // VM's SSH host key (private signer)
	VMHostKeyPublic          ssh.PublicKey      // VM's SSH host key (public) - for verification
	VMHostKeyPrivateKeyBytes []byte             // VM's SSH host key (raw private key bytes) - for injection
	VMHostKeyPrivate         ed25519.PrivateKey // VM's SSH host key (raw private key) - for explicit zeroing
	InitramfsPath            string             // Path to temp initramfs file (contains sensitive key material)
	Disk                     string
	Timeout                  time.Duration
	SSHBuildClient           *ssh.Client // SSH client for the build environment, may not have privileges
	SSHControlBuildClient    *ssh.Client // SSH client for control operations in the build environment, has privileges
	SSHControlClient         *ssh.Client // SSH client for unrestricted control environment, has privileges
	QemuPID                  int
	RunAsGID                 string
}
