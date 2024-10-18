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

package container

import (
	"os/exec"
	"reflect"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
)

func TestBubblewrapCmd(t *testing.T) {
	tests := []struct {
		name     string
		expected *exec.Cmd
	}{
		{
			name: "With default UID and GID",
			expected: exec.Command("bwrap",
				"--bind",
				"",
				"/",
				"--unshare-pid",
				"--die-with-parent",
				"--dev",
				"/dev",
				"--proc",
				"/proc",
				"--chdir",
				"/home/build",
				"--clearenv",
				"--unshare-user",
				"--uid",
				DefaultUID,
				"--gid",
				DefaultGID,
				"--new-session",
				"--unshare-net",
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			bw := &bubblewrap{}

			args := make([]string, 0)

			cmd := bw.cmd(ctx, new(Config), false, nil, args...)
			if cmd.Args == nil {
				t.Fatalf("cmd.Args should not be nil")
			}
			if !reflect.DeepEqual(tt.expected.Args, cmd.Args) {
				t.Fatalf("expected %v, found %v", tt.expected, cmd)
			}
		})
	}
}
