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

	"github.com/oec/goparsify"
)

var equal = goparsify.Exact("==")
var unequal = goparsify.Exact("!=")
var comps = goparsify.Any(equal, unequal)

var variableName = goparsify.Chars("a-z0-9.")
var variable = goparsify.Seq("${{", variableName, "}}").Map(func (n *goparsify.Result) {
	fmt.Printf("var = %s\n", n.Child[1].Token)
})

var value = goparsify.Any(goparsify.StringLit("'\""), variable)
var expr = goparsify.Seq(value, comps, value).Map(func (n *goparsify.Result) {
	fmt.Printf("expr = %v\n", n)

	switch n.Child[1].Token {
	case "==":
		n.Result = n.Child[0].Token == n.Child[2].Token
	case "!=":
		n.Result = n.Child[0].Token != n.Child[2].Token
	default:
		panic(fmt.Errorf("unrecognized op"))
	}
})

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

var and = goparsify.Exact("&&")
var or = goparsify.Exact("||")
var chain = goparsify.Any(and, or)
var combinedExpr = goparsify.Seq(expr, chain, expr).Map(combineOp)

var exprChain = goparsify.Some(goparsify.Any(combinedExpr, expr), chain).Map(collapseOp)

var group = goparsify.Seq("(", goparsify.Cut(), exprChain, ")").Map(func (n *goparsify.Result) {
	fmt.Printf("group = %v\n", n)

	n.Result = n.Child[2].Result
})
var groupOrExpr = goparsify.Any(group, exprChain)
var combinedGroup = goparsify.Seq(groupOrExpr, chain, groupOrExpr).Map(combineOp)

var groupChain = goparsify.Some(goparsify.Any(combinedGroup, groupOrExpr), chain).Map(collapseOp)

func Evaluate(expr string) (bool, error) {
	result, err := goparsify.Run(groupChain, expr, goparsify.UnicodeWhitespace)
	if err != nil {
		return false, err
	}

	if rbool, ok := result.(bool); ok {
		return rbool, nil
	}

	fmt.Printf("result = %v\n", result)

	return false, fmt.Errorf("got non-boolean result from parser")
}
