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

package sca

import "testing"

func TestProvidesVersionedShlib(t *testing.T) {
	const shlib = "libfoo.so.1"

	for _, tt := range []struct {
		name     string
		provides string
		want     bool
	}{
		{"versioned provides", "so-ver:libfoo.so.1=1.2.3", true},
		{"versioned provides with release", "so-ver:libfoo.so.1=1.2.3-r0", true},
		{"unparseable version", "so-ver:libfoo.so.1=not-a-version", false},
		{"no version at all", "so-ver:libfoo.so.1", false},
		{"different shared library", "so-ver:libother.so.2=1.2.3", false},
		{"unversioned so: provides", "so:libfoo.so.1=1.2.3", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := providesVersionedShlib(tt.provides, shlib); got != tt.want {
				t.Errorf("providesVersionedShlib(%q, %q) = %v, want %v", tt.provides, shlib, got, tt.want)
			}
		})
	}
}
