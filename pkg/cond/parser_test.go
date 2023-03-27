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

func TestVariableLookupWhitespace(t *testing.T) {
	result, err := Evaluate("${{ foo.bar }} == 'baz'", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{ foo.bar }} definitely equals baz")

	result, err = Evaluate("'baz' == ${{ foo.bar }}", placeholderLookup)
	require.NoErrorf(t, err, "got error: %v", err)
	require.Equal(t, true, result, "${{ foo.bar }} definitely equals baz")
}
