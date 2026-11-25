package version

import (
	"fmt"
	"strings"
)

const (
	// MaxExpressionDepth is the maximum number of nested grouping and negation
	// levels accepted in a version constraint expression. Expressions that
	// exceed this bound are rejected as syntax errors while parsing, before any
	// recursion can grow the stack.
	MaxExpressionDepth = 64

	// MaxExpressionTerms is the maximum number of leaf version terms accepted
	// in a single version constraint expression. Expressions that exceed this
	// bound are rejected as syntax errors while parsing. The parser is a single
	// pass over the input, so rejecting an over-long expression is O(limit).
	MaxExpressionTerms = 1024
)

// expressionNodeKind identifies the kind of node in a parsed version constraint
// expression.
type expressionNodeKind uint8

const (
	nodeLeaf expressionNodeKind = iota
	nodeAnd
	nodeOr
	nodeNot
)

// expressionNode is a node in the parsed constraint expression tree. The tree
// is immutable after parsing and safe for concurrent evaluation.
type expressionNode struct {
	kind     expressionNodeKind
	unit     rangeUnit
	children []expressionNode
}

// constraintExpressionParser is a single-pass recursive descent parser for
// version constraint expressions.
//
//	expression := orExpr
//	orExpr     := andExpr ( "||" andExpr )*
//	andExpr    := unaryExpr ( "," unaryExpr )*
//	unaryExpr  := "!" unaryExpr | primary
//	primary    := "(" expression ")" | leaf
//
// A leaf is any run of version characters (including quoted regions) that is
// not one of the structural tokens above. Single "|" characters are ignored
// for backwards compatibility, matching the historical scanner behavior.
//
// Exclusion is expressed with logical negation: "range, !(sub-range)" means
// "range and not sub-range", which carves the excluded versions out of the
// surrounding range. Because "!" is a normal unary operator it composes freely
// with grouping and with OR at any depth.
type constraintExpressionParser struct {
	input string
	pos   int
	terms int
	depth int
	// simple is true when the expression only uses the historical flat
	// AND/OR syntax (no grouping and no negation). It is used to decide whether
	// an external semantic-version constraint can be used as a fast path.
	simple bool
}

// parseConstraintExpression parses a constraint expression into an immutable
// expression tree. A nil node is returned for an empty input.
func parseConstraintExpression(input string) (*expressionNode, bool, error) {
	if strings.TrimSpace(input) == "" {
		return nil, true, nil
	}

	p := &constraintExpressionParser{
		input:  input,
		simple: true,
	}
	p.skipSpace()
	node, err := p.parseOr()
	if err != nil {
		return nil, false, err
	}

	p.skipSpace()
	if p.pos < len(p.input) {
		// parseOr stops only at a closing parenthesis; anything left over is
		// an unexpected token at the top level.
		return nil, false, newSyntaxError(p.input, p.pos, "unexpected token")
	}

	if node == nil {
		return nil, false, newSyntaxError(p.input, p.firstNonSpace(), "expression contains no version constraints")
	}

	return node, p.simple, nil
}

func (p *constraintExpressionParser) parseOr() (*expressionNode, error) {
	var children []expressionNode
	expectOperand := true

	for {
		p.skipSpace()
		if p.eof() || p.at(')') {
			break
		}

		if p.atOr() {
			p.pos += 2
			expectOperand = true
			continue
		}

		if !expectOperand {
			return nil, newSyntaxError(p.input, p.pos, "expected ',' or '||' between version constraints")
		}

		node, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		if node != nil {
			children = append(children, *node)
			expectOperand = false
		}
	}

	return collapse(nodeOr, children), nil
}

func (p *constraintExpressionParser) parseAnd() (*expressionNode, error) {
	var children []expressionNode
	expectOperand := true

	for {
		p.skipSpace()
		if p.eof() || p.at(')') || p.atOr() {
			break
		}

		if p.at(',') {
			p.pos++
			expectOperand = true
			continue
		}

		if !expectOperand {
			return nil, newSyntaxError(p.input, p.pos, "expected ',' or '||' between version constraints")
		}

		node, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if node != nil {
			children = append(children, *node)
			expectOperand = false
		}
	}

	return collapse(nodeAnd, children), nil
}

func (p *constraintExpressionParser) parseUnary() (*expressionNode, error) {
	p.skipSpace()
	if p.at('!') {
		start := p.pos
		p.pos++
		p.simple = false

		if err := p.enter(start); err != nil {
			return nil, err
		}
		defer p.leave()

		p.skipSpace()
		if p.eof() || p.at(')') || p.at(',') || p.atOr() {
			return nil, newSyntaxError(p.input, start, "expected an expression after '!'")
		}

		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if child == nil {
			return nil, newSyntaxError(p.input, start, "expected an expression after '!'")
		}
		return &expressionNode{kind: nodeNot, children: []expressionNode{*child}}, nil
	}

	return p.parsePrimary()
}

func (p *constraintExpressionParser) parsePrimary() (*expressionNode, error) {
	p.skipSpace()

	if p.at('(') {
		start := p.pos
		p.pos++
		p.simple = false

		if err := p.enter(start); err != nil {
			return nil, err
		}
		defer p.leave()

		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}

		p.skipSpace()
		if !p.at(')') {
			return nil, newSyntaxError(p.input, start, "unclosed '('")
		}
		if node == nil {
			return nil, newSyntaxError(p.input, p.pos, "empty group")
		}
		p.pos++
		return node, nil
	}

	if p.at(')') {
		return nil, newSyntaxError(p.input, p.pos, "unexpected ')'")
	}

	if p.eof() {
		return nil, nil
	}

	return p.parseLeaf()
}

func (p *constraintExpressionParser) parseLeaf() (*expressionNode, error) {
	start := p.pos
	var buf strings.Builder

	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		switch {
		case ch == ',' || ch == '(' || ch == ')':
			return p.finishLeaf(start, buf.String())
		case ch == '|' && p.pos+1 < len(p.input) && p.input[p.pos+1] == '|':
			return p.finishLeaf(start, buf.String())
		case ch == '\'' || ch == '"':
			quoted, err := p.scanQuoted(ch)
			if err != nil {
				return nil, err
			}
			buf.WriteString(quoted)
		case ch == '`':
			// raw string literal (the historical tokenizer accepted these)
			start := p.pos
			end := strings.IndexByte(p.input[start+1:], '`')
			if end < 0 {
				return nil, newSyntaxError(p.input, start, "unbalanced quotes")
			}
			p.pos = start + 1 + end + 1
			buf.WriteString(p.input[start:p.pos])
		case ch == '/' && p.pos+1 < len(p.input) && p.input[p.pos+1] == '/':
			// the historical tokenizer skipped comments; preserve that behavior
			p.pos += 2
			for p.pos < len(p.input) && p.input[p.pos] != '\n' {
				p.pos++
			}
		case ch == '/' && p.pos+1 < len(p.input) && p.input[p.pos+1] == '*':
			end := strings.Index(p.input[p.pos+2:], "*/")
			if end < 0 {
				return nil, newSyntaxError(p.input, p.pos, "unterminated comment")
			}
			p.pos += 2 + end + 2
		case ch == '|':
			// historically a single pipe is ignored rather than treated as
			// version content
			p.pos++
		case isConstraintSpace(ch):
			// whitespace between version tokens is not significant, matching
			// the historical scanner behavior
			p.pos++
		default:
			buf.WriteByte(ch)
			p.pos++
		}
	}

	return p.finishLeaf(start, buf.String())
}

func (p *constraintExpressionParser) finishLeaf(start int, raw string) (*expressionNode, error) {
	if raw == "" {
		return nil, nil
	}

	p.terms++
	if p.terms > MaxExpressionTerms {
		return nil, newSyntaxError(p.input, start, fmt.Sprintf("expression exceeds the maximum of %d version terms", MaxExpressionTerms))
	}

	unit, err := parseRange(raw)
	if err != nil {
		// Do not pass the lower-level error through to callers; classify it into
		// a stable reason so the outward error stays comparable and printable.
		return nil, newSyntaxError(p.input, start, fmt.Sprintf("invalid version constraint term %q (%s)", raw, classifyTermError(err)))
	}
	if unit == nil {
		return nil, newSyntaxError(p.input, start, "invalid version constraint term")
	}

	return &expressionNode{kind: nodeLeaf, unit: *unit}, nil
}

// classifyTermError reduces a leaf-level parse error to a stable, printable
// reason. Leaf-level errors are internal to the grammar layer and must not leak
// verbatim through the public error type.
func classifyTermError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unprocessable prefix"):
		return "unrecognized prefix"
	case strings.Contains(msg, "unbalanced quotes"):
		return "unbalanced quotes"
	case strings.Contains(msg, "potentially is a version constraint expression"):
		return "unexpected comparison operator"
	case strings.Contains(msg, "unable to parse constraint operator"):
		return "unrecognized operator"
	default:
		return "unparseable term"
	}
}

// scanQuoted consumes a single- or double-quoted literal, returning the raw
// text including the quotes. Parentheses, commas and pipes inside the literal
// are version content, not syntax.
func (p *constraintExpressionParser) scanQuoted(quote byte) (string, error) {
	start := p.pos
	i := p.pos + 1
	for i < len(p.input) {
		switch p.input[i] {
		case '\\':
			i += 2
			continue
		case quote:
			p.pos = i + 1
			return p.input[start:p.pos], nil
		}
		i++
	}
	return "", newSyntaxError(p.input, start, "unbalanced quotes")
}

func (p *constraintExpressionParser) enter(start int) error {
	p.depth++
	if p.depth > MaxExpressionDepth {
		return newSyntaxError(p.input, start, fmt.Sprintf("expression exceeds the maximum nesting depth of %d", MaxExpressionDepth))
	}
	return nil
}

func (p *constraintExpressionParser) leave() {
	p.depth--
}

func (p *constraintExpressionParser) at(ch byte) bool {
	return p.pos < len(p.input) && p.input[p.pos] == ch
}

func (p *constraintExpressionParser) atOr() bool {
	return p.pos+1 < len(p.input) && p.input[p.pos] == '|' && p.input[p.pos+1] == '|'
}

func (p *constraintExpressionParser) eof() bool {
	return p.pos >= len(p.input)
}

func (p *constraintExpressionParser) skipSpace() {
	for p.pos < len(p.input) {
		if isConstraintSpace(p.input[p.pos]) {
			p.pos++
			continue
		}
		// the historical tokenizer skipped Go-style comments; preserve that
		if p.input[p.pos] == '/' && p.pos+1 < len(p.input) {
			switch p.input[p.pos+1] {
			case '/':
				p.pos += 2
				for p.pos < len(p.input) && p.input[p.pos] != '\n' {
					p.pos++
				}
				continue
			case '*':
				if end := strings.Index(p.input[p.pos+2:], "*/"); end >= 0 {
					p.pos += 2 + end + 2
					continue
				}
			}
		}
		break
	}
}

func (p *constraintExpressionParser) firstNonSpace() int {
	for i := 0; i < len(p.input); i++ {
		if !isConstraintSpace(p.input[i]) {
			return i
		}
	}
	return 0
}

func isConstraintSpace(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// collapse builds an AND/OR node, flattening nested nodes of the same kind and
// returning a single child directly when possible.
func collapse(kind expressionNodeKind, children []expressionNode) *expressionNode {
	var flat []expressionNode
	for _, child := range children {
		if child.kind == kind {
			flat = append(flat, child.children...)
			continue
		}
		flat = append(flat, child)
	}

	switch len(flat) {
	case 0:
		return nil
	case 1:
		return &flat[0]
	default:
		return &expressionNode{kind: kind, children: flat}
	}
}
