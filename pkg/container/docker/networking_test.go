// Copyright 2026 Chainguard, Inc.
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

import "testing"

// TestDockerNetworkMode asserts the Docker runner selects NetworkMode "none"
// (loopback only, no route off-box) when the networking capability is
// disabled, and the default NetworkMode otherwise.
func TestDockerNetworkMode(t *testing.T) {
	for _, tt := range []struct {
		name       string
		networking bool
		want       string
	}{
		{"networking enabled", true, ""},
		{"networking disabled", false, "none"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(dockerNetworkMode(tt.networking)); got != tt.want {
				t.Fatalf("networking=%v: NetworkMode=%q, want %q", tt.networking, got, tt.want)
			}
		})
	}
}
