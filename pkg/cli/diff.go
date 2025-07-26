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

// Package cli provides compatibility aliases for functions that have been moved.
// Deprecated: The Diff function has been moved to pkg/util.
package cli

import (
	"chainguard.dev/melange/pkg/util"
)

// Diff is a compatibility wrapper for the function that has been moved to pkg/util.
// Deprecated: Use util.Diff instead. This function will be removed in a future version.
func Diff(oldName string, old []byte, newName string, new []byte, comments bool) []byte {
	return util.Diff(oldName, old, newName, new, comments)
}
