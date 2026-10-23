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

package build

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/config"
)

var uriCredentialStrip = regexp.MustCompile(`sed -e 's\|://[^']*\|://\|' -e 's\|\[\?#\]\.\*\$\|\|'`)

// The by-URL lookup and the .uri records must normalise a URL identically, or
// a record stops matching its own lookup. A userinfo may contain '@', so the
// strip has to run to the last one in the authority.
func TestSourceURICredentialStrip(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("runs shell commands")
	}
	for _, tool := range []string{"sh", "sed"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}

	found := make([]string, 0, 3)
	for _, p := range []config.Pipeline{
		{Uses: "fetch", With: map[string]string{"uri": "https://h/x", "expected-sha256": strings.Repeat("0", 64)}},
		{Uses: "git-checkout", With: map[string]string{"repository": "https://h/r", "destination": "d"}},
	} {
		sm := &SubstitutionMap{Substitutions: map[string]string{
			config.SubstitutionPackageName: "hello", config.SubstitutionPackageVersion: "1.0",
		}}
		require.NoError(t, (&Compiled{}).compilePipeline(t.Context(), sm, &p, nil))
		found = append(found, uriCredentialStrip.FindAllString(p.Pipeline[0].Runs, -1)...)
	}
	require.Len(t, found, 3, "fetch lookup, fetch record, git-checkout record")
	require.Equal(t, found[0], found[1])
	require.Equal(t, found[0], found[2])

	for in, want := range map[string]string{
		"https://u:p@ss@h/x?t=1":   "https://h/x",
		"https://u:pw@h/x":         "https://h/x",
		"https://h/@scope/pkg.tgz": "https://h/@scope/pkg.tgz",
		"https://h?x=a@b":          "https://h",
		"https://u:p@[::1]:8080/x": "https://[::1]:8080/x",
		"ssh://git@h:22/r":         "ssh://h:22/r",
		"git@h:o/r":                "git@h:o/r",
	} {
		out, err := exec.CommandContext(t.Context(), "sh", "-c", `printf '%s\n' "$1" | `+found[0], "sh", in).CombinedOutput()
		require.NoError(t, err, string(out))
		require.Equal(t, want+"\n", string(out), in)
	}
}
