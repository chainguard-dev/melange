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

package build

import (
	"testing"

	"chainguard.dev/melange/pkg/config"
)

func names(batches [][]config.Subpackage) [][]string {
	out := make([][]string, len(batches))
	for i, b := range batches {
		for _, sp := range b {
			out[i] = append(out[i], sp.Name)
		}
	}
	return out
}

func sub(name string, parallel bool) config.Subpackage {
	return config.Subpackage{Name: name, Parallel: parallel}
}

func TestBatchSubpackages(t *testing.T) {
	tests := []struct {
		name            string
		subpackages     []config.Subpackage
		parallelAllowed bool
		want            [][]string
	}{
		{
			name:            "empty",
			subpackages:     nil,
			parallelAllowed: true,
			want:            nil,
		},
		{
			name:            "all sequential",
			subpackages:     []config.Subpackage{sub("a", false), sub("b", false), sub("c", false)},
			parallelAllowed: true,
			want:            [][]string{{"a"}, {"b"}, {"c"}},
		},
		{
			name:            "all parallel merge into one batch",
			subpackages:     []config.Subpackage{sub("a", true), sub("b", true), sub("c", true)},
			parallelAllowed: true,
			want:            [][]string{{"a", "b", "c"}},
		},
		{
			name: "parallel batches separated by a sync barrier",
			subpackages: []config.Subpackage{
				sub("a", true), sub("b", true),
				sub("sync", false),
				sub("c", true), sub("d", true),
			},
			parallelAllowed: true,
			want:            [][]string{{"a", "b"}, {"sync"}, {"c", "d"}},
		},
		{
			name: "leading and trailing sync",
			subpackages: []config.Subpackage{
				sub("s1", false),
				sub("a", true), sub("b", true),
				sub("s2", false),
			},
			parallelAllowed: true,
			want:            [][]string{{"s1"}, {"a", "b"}, {"s2"}},
		},
		{
			name:            "lone parallel is its own batch",
			subpackages:     []config.Subpackage{sub("a", false), sub("b", true), sub("c", false)},
			parallelAllowed: true,
			want:            [][]string{{"a"}, {"b"}, {"c"}},
		},
		{
			name: "parallel disabled forces sequential",
			subpackages: []config.Subpackage{
				sub("a", true), sub("b", true), sub("c", true),
			},
			parallelAllowed: false,
			want:            [][]string{{"a"}, {"b"}, {"c"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := names(batchSubpackages(tt.subpackages, tt.parallelAllowed))
			if len(got) != len(tt.want) {
				t.Fatalf("got %d batches %v, want %d batches %v", len(got), got, len(tt.want), tt.want)
			}
			for i := range got {
				if len(got[i]) != len(tt.want[i]) {
					t.Fatalf("batch %d: got %v, want %v", i, got[i], tt.want[i])
				}
				for j := range got[i] {
					if got[i][j] != tt.want[i][j] {
						t.Fatalf("batch %d: got %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}
