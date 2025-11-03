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
	"fmt"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
)

func TestBubblewrapCmd(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedArgs string
	}{
		{
			name:         "With default UID and GID",
			config:       new(Config),
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", buildUserID, buildUserID),
		},
		{
			name:         "With config RunAs",
			config:       &Config{RunAsUID: "65535"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "65535"),
		},
		{
			name:         "With config RunAs with distinct UID and GID",
			config:       &Config{RunAsUID: "65535", RunAsGID: "1000"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "1000"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			args := make([]string, 0)

			cmd := new(bubblewrap).cmd(ctx, tt.config, false, nil, args...)
			if cmd.Args == nil {
				t.Fatalf("cmd.Args should not be nil")
			}
			if !strings.Contains(strings.Join(cmd.Args, " "), tt.expectedArgs) {
				t.Fatalf("expected %v, found %v", tt.expectedArgs, cmd.Args)
			}
		})
	}
}
