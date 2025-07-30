// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_stringToIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic_colon",
			input:    "foo:bar",
			expected: "foo-bar", // Colons replaced with dashes.
		},
		{
			name:     "basic_slash",
			input:    "foo/bar",
			expected: "foo-bar", // Slashes replaced with dashes.
		},
		{
			name:     "space_replacement",
			input:    "foo bar",
			expected: "fooC32bar", // Spaces encoded as Unicode prefix.
		},
		{
			name:     "mixed_colon_and_slash",
			input:    "foo:bar/baz",
			expected: "foo-bar-baz", // Mixed colons and slashes replaced with dashes.
		},
		{
			name:     "valid_characters_unchanged",
			input:    "example-valid.123",
			expected: "example-valid.123", // Valid characters remain unchanged.
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := stringToIdentifier(test.input)
			require.Equal(t, test.expected, result, "unexpected result for input %q", test.input)
		})
	}
}
