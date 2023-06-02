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

	"github.com/ijt/goparsify"
)

func combineOp(n *goparsify.Result) {
	switch n.Child[1].Token {
	case "&&":
		n.Result = n.Child[0].Result == true && n.Child[2].Result == true
	case "||":
		n.Result = n.Child[0].Result == true || n.Child[2].Result == true
	default:
		panic(fmt.Errorf("unrecognized op"))
	}
}

func collapseOp(n *goparsify.Result) {
	n.Result = true
	for _, child := range n.Child {
		if child.Result != true {
			n.Result = false
			return
		}
	}
}

func comparisonOp(n *goparsify.Result) {
	switch n.Child[1].Token {
	case "==":
		n.Result = n.Child[0].Token == n.Child[2].Token
	case "!=":
		n.Result = n.Child[0].Token != n.Child[2].Token
	default:
		panic(fmt.Errorf("unrecognized op"))
	}
}

// A VariableLookupFunction designates how variables should be
// resolved when evaluating expressions.
type VariableLookupFunction func(key string) (string, error)

// NullLookup returns an empty value for any requested variable and
// does not return an error.  This is the default variable lookup
// function used by Evaluate.
func NullLookup(key string) (string, error) {
	return "", nil
}

// Evaluate evaluates an input expression.
// Expressions are groups of string values combined with equal or unequal
// comparators.  The order of comparison operations can be designated using
// groups enclosed inside parenthesis.
// An optional VariableLookupFunction can be provided to provide variable
// lookups.
func Evaluate(inputExpr string, lookupFns ...VariableLookupFunction) (bool, error) {
	lookupFn := NullLookup

	if len(lookupFns) > 0 {
		lookupFn = lookupFns[0]
	}

	equal := goparsify.Exact("==")
	unequal := goparsify.Exact("!=")
	comps := goparsify.Any(equal, unequal)

	variableName := goparsify.Chars("a-zA-Z0-9.\\-_")
	variable := goparsify.Seq("${{", variableName, "}}").Map(func(n *goparsify.Result) {
		if resolved, err := lookupFn(n.Child[1].Token); err == nil {
			n.Token = resolved
			n.Result = resolved
		}
	})

	value := goparsify.Any(goparsify.StringLit("'\""), variable)
	expr := goparsify.Seq(value, comps, value).Map(comparisonOp)

	and := goparsify.Exact("&&")
	or := goparsify.Exact("||")
	chain := goparsify.Any(and, or)
	combinedExpr := goparsify.Seq(expr, chain, expr).Map(combineOp)

	exprChain := goparsify.Some(goparsify.Any(combinedExpr, expr), chain).Map(collapseOp)

	group := goparsify.Seq("(", goparsify.Cut(), exprChain, ")").Map(func(n *goparsify.Result) {
		n.Result = n.Child[2].Result
	})
	groupOrExpr := goparsify.Any(group, exprChain)
	combinedGroup := goparsify.Seq(groupOrExpr, chain, groupOrExpr).Map(combineOp)

	groupChain := goparsify.Some(goparsify.Any(combinedGroup, groupOrExpr), chain).Map(collapseOp)

	result, _, err := goparsify.Run(groupChain, inputExpr, goparsify.UnicodeWhitespace)
	if err != nil {
		return false, err
	}

	if rbool, ok := result.(bool); ok {
		return rbool, nil
	}

	return false, fmt.Errorf("got non-boolean result from parser")
}
