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
	"errors"
	"fmt"
	"strings"
)

func Subst(inputExpr string, lookupFns ...VariableLookupFunction) (string, error) {
	lookupFn := NullLookup

	if len(lookupFns) > 0 {
		lookupFn = lookupFns[0]
	}

	var b strings.Builder
	b.Grow(len(inputExpr))

	var errs []error
	i := 0
	for i < len(inputExpr) {
		// Look for the next ${{ marker.
		idx := strings.Index(inputExpr[i:], "${{")
		if idx < 0 {
			// No more variables, write the rest.
			b.WriteString(inputExpr[i:])
			break
		}

		// Write text before the variable.
		b.WriteString(inputExpr[i : i+idx])
		i += idx + 3 // skip past ${{

		// Skip whitespace inside braces.
		for i < len(inputExpr) && isWhitespace(inputExpr[i]) {
			i++
		}

		// Read variable name.
		start := i
		for i < len(inputExpr) && isVarChar(inputExpr[i]) {
			i++
		}
		name := inputExpr[start:i]

		if name == "" {
			errs = append(errs, fmt.Errorf("empty variable name at position %d", start))
			continue
		}

		// Skip whitespace before }}.
		for i < len(inputExpr) && isWhitespace(inputExpr[i]) {
			i++
		}

		// Expect }}.
		if i+2 > len(inputExpr) || inputExpr[i:i+2] != "}}" {
			errs = append(errs, fmt.Errorf("unterminated variable reference %q at position %d", name, start))
			continue
		}
		i += 2

		resolved, err := lookupFn(name)
		if err != nil {
			errs = append(errs, err)
		} else {
			b.WriteString(resolved)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return "", err
	}

	return b.String(), nil
}
