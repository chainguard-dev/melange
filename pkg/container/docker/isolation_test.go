// Copyright 2024 Chainguard, Inc.
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

package docker

import (
	"strings"
	"testing"

	mcontainer "chainguard.dev/melange/pkg/container"
)

func TestDockerIsolationCommand(t *testing.T) {
	iso := &mcontainer.Isolation{ID: "abc123", SubpkgName: "foo-dev"}
	cmd := dockerIsolationCommand(iso, []string{"/bin/sh", "-c", "echo hi"})

	// The command runs inside an unshare(2) mount namespace.
	if len(cmd) < 4 || cmd[0] != "unshare" || cmd[1] != "-m" {
		t.Fatalf("expected unshare -m prefix, got %v", cmd[:min(4, len(cmd))])
	}

	script := cmd[len(cmd)-1]
	for _, s := range []string{
		"mount --make-rprivate /",
		// overlay for /home/build.
		"lowerdir=/home/build,upperdir=/tmp/parallel-build-abc123/upper,workdir=/tmp/parallel-build-abc123/work",
		// read-only bind of the captured shared melange-out.
		"mount -o remount,ro,bind /home/build/melange-out",
		// read-write bind of this subpackage onto the host workspace.
		"mount --bind /tmp/parallel-build-abc123/hostout/foo-dev /home/build/melange-out/foo-dev",
		// finally exec the original command.
		"exec /bin/sh -c 'echo hi'",
	} {
		if !strings.Contains(script, s) {
			t.Errorf("isolation script missing %q\nfull script:\n%s", s, script)
		}
	}
}
