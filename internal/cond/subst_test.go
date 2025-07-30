// Copyright 2023 Chainguard, Inc.
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

package cond

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSubstSimple(t *testing.T) {
	doc := "Hello ${{foo.bar}}!"
	expected := "Hello baz!"
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func TestSubstMulti(t *testing.T) {
	doc := "Hello ${{foo.bar}} ${{foo.bar}}!"
	expected := "Hello baz baz!"
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func TestSubstVarWhitespace(t *testing.T) {
	doc := "Hello ${{ foo.bar }} ${{foo.bar}}!"
	expected := "Hello baz baz!"
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func TestSubstVarUnderscore(t *testing.T) {
	doc := "Hello ${{foo.BAR_BAZ}}!"
	expected := "Hello bar-baz!"
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func TestSubstVarWhitespaceNewline(t *testing.T) {
	doc := `Hello
${{ foo.bar }}
${{foo.bar}}
!`
	expected := `Hello
baz
baz
!`
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func fakeLookup(key string) (string, error) {
	return "a", nil
}

func TestSubstVarWhitespaceExactWhitespace(t *testing.T) {
	doc := `Hello
  ${{ foo.bar }}
    ${{foo.bar}}
!`
	expected := `Hello
  baz
    baz
!`
	result, err := Subst(doc, placeholderLookup)

	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, expected, result, "result does not match expected result")
}

func TestSubstVarShellFragment(t *testing.T) {
	doc := `if [ "${{inputs.expected-sha256}}" == "" ] && [ "${{inputs.expected-sha512}}" == "" ]; then
  printf "One of expected-sha256 or expected-sha512 is required"
  exit 1
fi`
	_, err := Subst(doc, fakeLookup)

	require.NoErrorf(t, err, "got error: %v", err)
}
