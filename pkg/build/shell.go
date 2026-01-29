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
	"github.com/kballard/go-shellquote"
)

// quoteShellArg safely quotes a string for embedding in shell commands.
// It uses go-shellquote to properly escape all shell metacharacters,
// preventing shell injection when user-controlled values are embedded in /bin/sh -c scripts.
//
// Example: x'$(cmd)'x → 'x'"'"'$(cmd)'"'"'x' → shell treats as literal string "x'$(cmd)'x"
//
// This function is used to sanitize paths and directories before embedding them in shell commands
// to prevent command injection attacks via variable substitution (e.g., ${{vars.*}}, ${{inputs.*}}).
//
// See GHSA-vqqr-rmpc-hhg2 for vulnerability details.
func quoteShellArg(s string) string {
	return shellquote.Join(s)
}
