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
	"strings"
)

// A VariableLookupFunction designates how variables should be
// resolved when evaluating expressions.
type VariableLookupFunction func(key string) (string, error)

// NullLookup returns an empty value for any requested variable and
// does not return an error.  This is the default variable lookup
// function used by Evaluate.
func NullLookup(key string) (string, error) {
	return "", nil
}

// parser is a simple recursive descent parser for condition expressions.
type parser struct {
	input    string
	pos      int
	lookupFn VariableLookupFunction
}

func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func (p *parser) skipWhitespace() {
	for p.pos < len(p.input) && isWhitespace(p.input[p.pos]) {
		p.pos++
	}
}

func (p *parser) peek(s string) bool {
	p.skipWhitespace()
	return p.pos+len(s) <= len(p.input) && p.input[p.pos:p.pos+len(s)] == s
}

func (p *parser) expect(s string) error {
	p.skipWhitespace()
	if p.pos+len(s) > len(p.input) || p.input[p.pos:p.pos+len(s)] != s {
		return fmt.Errorf("expected %q at position %d", s, p.pos)
	}
	p.pos += len(s)
	return nil
}

func isVarChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
}

// parseValue parses a string literal ('...' or "...") or a variable (${{...}}).
func (p *parser) parseValue() (string, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return "", fmt.Errorf("unexpected end of input at position %d", p.pos)
	}

	// String literal
	if p.input[p.pos] == '\'' || p.input[p.pos] == '"' {
		quote := p.input[p.pos]
		p.pos++
		var b strings.Builder
		for p.pos < len(p.input) && p.input[p.pos] != quote {
			if p.input[p.pos] == '\\' && p.pos+1 < len(p.input) {
				p.pos++ // skip backslash
				switch p.input[p.pos] {
				case '\\', '\'', '"':
					b.WriteByte(p.input[p.pos])
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					// Preserve unknown escapes as-is.
					b.WriteByte('\\')
					b.WriteByte(p.input[p.pos])
				}
			} else {
				b.WriteByte(p.input[p.pos])
			}
			p.pos++
		}
		if p.pos >= len(p.input) {
			return "", fmt.Errorf("unterminated string literal at position %d", p.pos)
		}
		p.pos++ // consume closing quote
		return b.String(), nil
	}

	// Variable: ${{name}}
	if p.peek("${{") {
		p.pos += 3 // consume ${{
		p.skipWhitespace()
		start := p.pos
		for p.pos < len(p.input) && isVarChar(p.input[p.pos]) {
			p.pos++
		}
		if p.pos == start {
			return "", fmt.Errorf("empty variable name at position %d", p.pos)
		}
		name := p.input[start:p.pos]
		p.skipWhitespace()
		if err := p.expect("}}"); err != nil {
			return "", fmt.Errorf("unterminated variable reference %q at position %d: %w", name, start, err)
		}
		resolved, err := p.lookupFn(name)
		if err != nil {
			return "", fmt.Errorf("error resolving variable %q at position %d: %w", name, start, err)
		}
		return resolved, nil
	}

	return "", fmt.Errorf("unexpected character %q at position %d", p.input[p.pos], p.pos)
}

// parseComparison parses: value ('==' | '!=') value
func (p *parser) parseComparison() (bool, error) {
	lhs, err := p.parseValue()
	if err != nil {
		return false, err
	}

	p.skipWhitespace()
	if p.pos+2 > len(p.input) {
		return false, fmt.Errorf("expected comparison operator at position %d", p.pos)
	}

	op := p.input[p.pos : p.pos+2]
	if op != "==" && op != "!=" {
		return false, fmt.Errorf("expected '==' or '!=' at position %d, got %q", p.pos, op)
	}
	p.pos += 2

	rhs, err := p.parseValue()
	if err != nil {
		return false, err
	}

	if op == "==" {
		return lhs == rhs, nil
	}
	return lhs != rhs, nil
}

// parseAtom parses a grouped expression or a comparison.
func (p *parser) parseAtom() (bool, error) {
	p.skipWhitespace()
	if p.pos < len(p.input) && p.input[p.pos] == '(' {
		p.pos++ // consume '('
		result, err := p.parseExpr()
		if err != nil {
			return false, err
		}
		if err := p.expect(")"); err != nil {
			return false, fmt.Errorf("expected ')' at position %d: %w", p.pos, err)
		}
		return result, nil
	}
	return p.parseComparison()
}

// parseExpr parses atoms chained with && and ||.
func (p *parser) parseExpr() (bool, error) {
	result, err := p.parseAtom()
	if err != nil {
		return false, err
	}

	for {
		p.skipWhitespace()
		if p.pos+2 > len(p.input) {
			break
		}
		op := p.input[p.pos : p.pos+2]
		if op != "&&" && op != "||" {
			break
		}
		p.pos += 2

		rhs, err := p.parseAtom()
		if err != nil {
			return false, err
		}

		switch op {
		case "&&":
			result = result && rhs
		case "||":
			result = result || rhs
		}
	}

	return result, nil
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

	p := &parser{
		input:    inputExpr,
		pos:      0,
		lookupFn: lookupFn,
	}

	result, err := p.parseExpr()
	if err != nil {
		return false, err
	}

	p.skipWhitespace()
	if p.pos != len(p.input) {
		return false, fmt.Errorf("unexpected trailing input at position %d: %q", p.pos, p.input[p.pos:])
	}

	return result, nil
}
