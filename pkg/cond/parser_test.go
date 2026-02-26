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

package cond

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExprLogic(t *testing.T) {
	result, err := Evaluate("'foo' == 'foo'")
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "result is non-true for 'foo' == 'foo'")

	result, err = Evaluate("'foo' != 'foo'")
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, false, result, "result is true for 'foo' != 'foo'")
}

func TestExprChainingAnd(t *testing.T) {
	result, err := Evaluate("'rabbit' == 'rabbit' && 'hare' == 'hare' && 'rabbit' != 'hare'")
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "result is non-true despite rabbits being rabbits, hares being hares, and rabbits not being hares")
}

func TestExprChainingOr(t *testing.T) {
	result, err := Evaluate("'rabbit' == 'hare' || 'lagomorph' == 'lagomorph'")
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "lagomorphs are lagomorphs, despite rabbits not being hares")
}

func TestExprChainingGroups(t *testing.T) {
	result, err := Evaluate("('rabbit' == 'rabbit' && 'hare' != 'hare') || 'lagomorph' == 'lagomorph'")
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "lagomorphs are lagomorphs, despite hares being hares")
}

func TextExprIncomplete(t *testing.T) {
	_, err := Evaluate("'foo' == ")
	require.Error(t, err)
}

func placeholderLookup(key string) (string, error) {
	if key == "foo.BAR_BAZ" {
		return "bar-baz", nil
	}

	if key == "foo.bar" {
		return "baz", nil
	}

	return "", fmt.Errorf("unknown key %s", key)
}

func TestVariableLookup(t *testing.T) {
	result, err := Evaluate("${{foo.bar}} == 'baz'", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{foo.bar}} definitely equals baz")

	result, err = Evaluate("'baz' == ${{foo.bar}}", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{foo.bar}} definitely equals baz")
}

func TestEvaluateUnterminatedVariable(t *testing.T) {
	_, err := Evaluate("${{foo.bar} == 'baz'", placeholderLookup)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unterminated variable reference")
	require.Contains(t, err.Error(), "foo.bar")
}

func TestStringLiteralEscapes(t *testing.T) {
	// Escaped double quote inside double-quoted string.
	result, err := Evaluate(`"hello \"world\"" == "hello \"world\""`)
	require.NoError(t, err)
	require.True(t, result)

	// Escaped backslash.
	result, err = Evaluate(`"a\\b" == "a\\b"`)
	require.NoError(t, err)
	require.True(t, result)

	// Escaped single quote inside single-quoted string.
	result, err = Evaluate(`'it\'s' == 'it\'s'`)
	require.NoError(t, err)
	require.True(t, result)

	// Newline and tab escapes.
	result, err = Evaluate(`"line1\nline2" == "line1\nline2"`)
	require.NoError(t, err)
	require.True(t, result)

	// Mismatch: escaped vs literal.
	result, err = Evaluate(`"a\\b" == "ab"`)
	require.NoError(t, err)
	require.False(t, result)
}

func FuzzEvaluate(f *testing.F) {
	// Seed with valid and interesting expressions.
	f.Add("'foo' == 'foo'")
	f.Add("'foo' != 'bar'")
	f.Add("${{foo.bar}} == 'baz'")
	f.Add("${{ foo.bar }} == 'baz'")
	f.Add(`"hello \"world\"" == "hello \"world\""`)
	f.Add(`"a\\b" == "a\\b"`)
	f.Add("('a' == 'a' && 'b' == 'b') || 'c' == 'd'")
	f.Add("${{")
	f.Add("${{ }}")
	f.Add("'unterminated")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		// Evaluate must never panic regardless of input.
		Evaluate(input, func(key string) (string, error) { //nolint:errcheck
			return "x", nil
		})
	})
}

func FuzzSubst(f *testing.F) {
	f.Add("Hello ${{foo.bar}}!")
	f.Add("${{foo}} ${{bar}}")
	f.Add("${{ foo.bar }}")
	f.Add("no variables here")
	f.Add("${{")
	f.Add("${{ }}")
	f.Add("${{foo.bar}")
	f.Add("")

	f.Fuzz(func(t *testing.T, input string) {
		// Subst must never panic regardless of input.
		Subst(input, func(key string) (string, error) { //nolint:errcheck
			return "x", nil
		})
	})
}

func TestVariableLookupWhitespace(t *testing.T) {
	result, err := Evaluate("${{ foo.bar }} == 'baz'", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{ foo.bar }} definitely equals baz")

	result, err = Evaluate("'baz' == ${{ foo.bar }}", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{ foo.bar }} definitely equals baz")

	// Tabs and newlines inside braces.
	result, err = Evaluate("${{\tfoo.bar\t}} == 'baz'", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "tabs inside variable braces should be accepted")

	result, err = Evaluate("${{\n foo.bar \n}} == 'baz'", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "newlines inside variable braces should be accepted")
}
