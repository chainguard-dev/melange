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

package container

import (
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
)

// TestBubblewrapNetworking asserts the bubblewrap runner unshares the network
// namespace (--unshare-net) when, and only when, the networking capability is
// disabled.
func TestBubblewrapNetworking(t *testing.T) {
	for _, tt := range []struct {
		name        string
		networking  bool
		wantUnshare bool
	}{
		{"networking enabled", true, false},
		{"networking disabled", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			cfg := &Config{Capabilities: Capabilities{Networking: tt.networking}}
			cmd := new(bubblewrap).cmd(ctx, cfg, false, nil)
			got := strings.Contains(strings.Join(cmd.Args, " "), "--unshare-net")
			if got != tt.wantUnshare {
				t.Fatalf("networking=%v: --unshare-net present=%v, want=%v\nargs: %s",
					tt.networking, got, tt.wantUnshare, strings.Join(cmd.Args, " "))
			}
		})
	}
}

// TestQemuNetdevArgs asserts the QEMU runner adds SLIRP restrict=on (guest
// network isolation) when, and only when, the networking capability is
// disabled, while always preserving the hostfwd control channel.
func TestQemuNetdevArgs(t *testing.T) {
	const sshAddr = "127.0.0.1:2022"
	const sshCtrlAddr = "127.0.0.1:2223"

	for _, tt := range []struct {
		name         string
		networking   bool
		wantRestrict bool
	}{
		{"networking enabled", true, false},
		{"networking disabled", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := qemuNetdevArgs(sshAddr, sshCtrlAddr, tt.networking)

			// hostfwd control channel must always be present so melange can
			// drive the guest over SSH.
			if !strings.Contains(got, "hostfwd=tcp:"+sshAddr+"-:22") ||
				!strings.Contains(got, "hostfwd=tcp:"+sshCtrlAddr+"-:2223") {
				t.Fatalf("hostfwd rules missing from netdev args: %s", got)
			}

			gotRestrict := strings.Contains(got, "restrict=on")
			if gotRestrict != tt.wantRestrict {
				t.Fatalf("networking=%v: restrict=on present=%v, want=%v\nargs: %s",
					tt.networking, gotRestrict, tt.wantRestrict, got)
			}
		})
	}
}
