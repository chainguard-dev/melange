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

	"github.com/ijt/goparsify"
)

func Subst(inputExpr string, lookupFns ...VariableLookupFunction) (string, error) {
	lookupFn := NullLookup

	if len(lookupFns) > 0 {
		lookupFn = lookupFns[0]
	}

	whiteSpace := goparsify.Many(goparsify.Exact(" "))
	variableName := goparsify.Chars("a-zA-Z0-9.\\-_")
	errs := []error{}
	variable := goparsify.Seq("${{", whiteSpace, variableName, whiteSpace, "}}").Map(func(n *goparsify.Result) {
		if resolved, err := lookupFn(n.Child[2].Token); err == nil {
			n.Token = resolved
			n.Result = resolved
		} else {
			errs = append(errs, err)
			n.Token = ""
			n.Result = ""
		}
	})

	text := goparsify.Until("${{")
	node := goparsify.Any(text, variable)

	document := goparsify.Many(node).Map(func(n *goparsify.Result) {
		tokens := []string{}
		for _, tok := range n.Child {
			tokens = append(tokens, tok.Token)
		}
		n.Result = strings.Join(tokens, "")
	})

	result, _, err := goparsify.Run(document, inputExpr, goparsify.NoWhitespace)
	if err != nil {
		return "", fmt.Errorf("parser error: %w", err)
	}

	if err := errors.Join(errs...); err != nil {
		return "", err
	}

	if rstr, ok := result.(string); ok {
		return rstr, nil
	}

	return "", fmt.Errorf("got non-string result from parser")
}
