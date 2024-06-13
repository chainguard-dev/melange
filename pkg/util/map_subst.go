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

package util

import (
	"fmt"
	"strconv"

	"chainguard.dev/melange/pkg/cond"
)

// Given a string and a map, replace the variables in the string with values in the map
func MutateStringFromMap(with map[string]string, input string) (string, error) {
	lookupWith := func(key string) (string, error) {
		if val, ok := with[key]; ok {
			return val, nil
		}

		nk := fmt.Sprintf("${{%s}}", key)
		if val, ok := with[nk]; ok {
			return val, nil
		}

		return "", fmt.Errorf("variable %s not defined", key)
	}

	return cond.Subst(input, lookupWith)
}

// Given a string and a map, replace the variables in the string with quoted values in the map.
// Currently, an "if" statement in a melange config can only have quoted strings or ${{variables}}
// as comparision values with == and !=. If we want to be able to resolve an "if" that can be fed
// back into melange, we need to maintain that requirement, so all variables get quoted once replaced.
func MutateAndQuoteStringFromMap(with map[string]string, input string) (string, error) {
	lookupWith := func(key string) (string, error) {
		if val, ok := with[key]; ok {
			return val, nil
		}

		nk := fmt.Sprintf("${{%s}}", key)
		if val, ok := with[nk]; ok {
			return strconv.Quote(val), nil
		}

		return "", fmt.Errorf("variable %s not defined", key)
	}

	return cond.Subst(input, lookupWith)
}
