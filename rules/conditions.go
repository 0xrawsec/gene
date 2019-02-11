package rules

import (
	"fmt"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
)

/////////////////////////////// Tokenizer //////////////////////////////////////

//Tokenizer structure
type Tokenizer struct {
	i        int
	tokens   []string
	expected []string
}

var (
	//ErrEOT End Of Tokens
	ErrEOT = fmt.Errorf("End of tokens")
	//ErrUnexpectedToken definition
	ErrUnexpectedToken = fmt.Errorf("Unexpected tokens")
	//ErrEmptyToken definition
	ErrEmptyToken = fmt.Errorf("Empty token")
)

//NewTokenizer creates and inits a new Tokenizer struct
func NewTokenizer(condition string) (c Tokenizer) {
	c.tokens = strings.Split(condition, " ")
	// split parathesis from other tokens
	for i := 0; i < len(c.tokens); i++ {
		token := c.tokens[i]
		if len(token) == 0 {
			c.tokens = append(c.tokens[:i], c.tokens[i+1:]...)
		}
		if len(token) > 1 {
			if token[0] == '(' {
				c.tokens[i] = token[1:]
				c.tokens = append(c.tokens[:i], append([]string{"("}, c.tokens[i:]...)...)
				continue
			}
			log.Debug(token)
			if token[0] == '!' {
				c.tokens[i] = token[1:]
				c.tokens = append(c.tokens[:i], append([]string{"!"}, c.tokens[i:]...)...)
				continue
			}
			brackets := make([]string, 0)
			for k := len(token) - 1; k > 0; k-- {
				if token[k] == ')' {
					brackets = append(brackets, ")")
					continue
				}
				break
			}
			c.tokens[i] = token[:len(token)-len(brackets)]
			c.tokens = append(c.tokens[:i+1], append(brackets, c.tokens[i+1:]...)...)
		}
	}
	return
}

//NextToken grabs the next token
func (t *Tokenizer) NextToken() (token string, err error) {
	if t.i >= len(t.tokens) {
		err = ErrEOT
		return
	}
	for _, token = range t.tokens[t.i:] {
		t.i++
		if token == " " {
			continue
		}
		return
	}
	return "", ErrEOT
}

//NextExpectedToken grabs the next token and returns it. ErrUnexpectedToken is returned
//if the token returned is not in the list of expected tokens
func (t *Tokenizer) NextExpectedToken(expects ...string) (token string, err error) {
	etok := datastructs.NewSyncedSet()
	for _, e := range expects {
		etok.Add(e)
	}
	token, err = t.NextToken()
	if err == ErrEOT {
		return
	}
	log.Debugf("Token: '%s'", token)
	if etok.Contains(token) || etok.Contains(string(token[0])) {
		return
	}
	log.Debugf("%s: '%s' not in %v", ErrUnexpectedToken, token, expects)
	return "", ErrUnexpectedToken
}

//ParseCondition parses a condition from a Tokenizer object
func (t *Tokenizer) ParseCondition(group, level int) (c ConditionElement, err error) {
	var token string
	log.Debugf("Tokens: %v", t.tokens[t.i:])

	token, err = t.NextExpectedToken("$", "!", "(", ")", "and", "&&", "AND", "or", "||", "OR")
	if err != nil {
		return
	}
	c.Level = level
	c.Group = group
	switch {
	case token[0] == '!':
		c.Negate = true
		c.Type = TypeNegate

	case token[0] == '$':
		c.Operand = token
		c.Type = TypeOperand

	case token[0] == '(':
		level++
		return t.ParseCondition(group, level)

	case token[0] == ')':
		group++
		level--
		return t.ParseCondition(group, level)

	default:
		switch token {
		case "and", "AND", "&&":
			c.Operator = '&'
			c.Type = TypeOperator
		case "or", "OR", "||":
			c.Operator = '|'
			c.Type = TypeOperator
		}
	}

	// Set the next condition
	next, err := t.ParseCondition(group, level)
	switch err {
	case nil:
		c.Next = &next
	case ErrEOT:
		// Don't set next element if EOT
		err = nil
	case ErrUnexpectedToken:
		return c, err
	}
	return
}

///////////////////////////////// Condition ////////////////////////////////////

const (
	//TypeOperand constant to type a ConditionElement
	TypeOperand = 0x1 << iota
	//TypeOperator constant to type a ConditionElement
	TypeOperator
	//TypeNegate constant to type a ConditionElement
	TypeNegate
)

// OperandReader interface
type OperandReader interface {
	// Return operand value and ok (true if operand found false otherwise)
	Read(string) (bool, bool)
}

// OperandMap defines a simple structure to implement OperandReader
type OperandMap map[string]bool

func (om OperandMap) Read(operand string) (value, ok bool) {
	value, ok = om[operand]
	return
}

//ConditionElement structure definition
type ConditionElement struct {
	Operand  string
	Operator rune
	Negate   bool
	Level    int
	Group    int
	Type     int
	Next     *ConditionElement
}

//GetOperands retrieves all the operands involed in a condition
func GetOperands(ce *ConditionElement) []string {
	out := make([]string, 0)
	set := datastructs.NewSyncedSet()
	e := ce
	for e != nil {
		if e.Type == TypeOperand {
			if !set.Contains(e.Operand) {
				out = append(out, e.Operand)
			}
			set.Add(e.Operand)
		}
		e = e.Next
	}
	return out
}

//Compute computes a given condition given the operands
func Compute(ce *ConditionElement, operands OperandReader) bool {
	nce, ret := compute(false, ce, operands)
	for nce != nil {
		nce, ret = compute(ret, nce, operands)
		log.Debug("We go out")
	}
	return ret
}

func nextCondEltLowerLevel(ce *ConditionElement) *ConditionElement {
	var e *ConditionElement
	// original condition element
	oe := ce
	for e = oe; e.Next != nil; e = e.Next {
		if e.Next.Level < oe.Level {
			return e.Next
		}
	}
	return e.Next
}

func compute(computed bool, ce *ConditionElement, operands OperandReader) (*ConditionElement, bool) {
	// Stop Condition
	if ce == nil {
		log.Debug("Any computation should finish here")
		return nil, computed
	}
	log.Debugf("computed:%t ce: %v", computed, ce)

	switch ce.Type {

	case TypeNegate:
		// Assume next is operand
		switch ce.Next.Type {
		case TypeOperand:
			if v, ok := operands.Read(ce.Next.Operand); ok {
				if ce.Next.Level == ce.Level && ce.Next.Group == ce.Group {
					return compute(!v, ce.Next.Next, operands)
				}
				nce, v := compute(false, ce.Next, operands)
				// before going on with negation we have to be sure that the
				// next element is a level down otherwise it means we are
				// in a parenthesis
				if nce != nil {
					if nce.Level > ce.Level {
						nce, v = compute(v, nce, operands)
					}
				}
				return compute(!v, nce, operands)
			}
			panic(fmt.Sprintf("Unkown Operand: %s", ce.Next.Operand))
		case TypeNegate:
			nce, v := compute(false, ce.Next, operands)
			return compute(!v, nce, operands)
		default:
			panic(fmt.Sprintf("%s cannot follow ! token", ce.Next))
		}

	case TypeOperator:
		switch ce.Operator {
		case '&':
			// Shortcut if computed is false
			if !computed {
				nce := nextCondEltLowerLevel(ce)
				return nce, false
			}
			nce, ret := compute(false, ce.Next, operands)
			ret = computed && ret
			return nce, ret
		case '|':
			// Shortcut if computed is true
			if computed {
				nce := nextCondEltLowerLevel(ce)
				log.Debugf("Shortcut taken: ce=%s nce=%s", ce, nce)
				return nce, true
			}
			nce, ret := compute(false, ce.Next, operands)
			ret = computed || ret
			return nce, ret
		}

	case TypeOperand:
		log.Debugf("Computing operand: %s", ce.Operand)
		if v, ok := operands.Read(ce.Operand); ok {
			if ce.Next != nil && ce.Next.Level != ce.Level {
				return ce.Next, v
			}
			return compute(v, ce.Next, operands)
		}
		panic(fmt.Sprintf("Unkown Operand: %s", ce.Operand))

	default:
		panic("Unkown type")
	}
	panic("Should not go there")
	//return nil, false
}

func (c *ConditionElement) String() string {
	if c.Negate {
		if c.Next != nil {
			return fmt.Sprintf("!%s:%d|%d %c %s", c.Operand, c.Level, c.Group, c.Operator, c.Next)
		}
		return fmt.Sprintf("!%s:%d|%d", c.Operand, c.Level, c.Group)
	}
	if c.Next != nil {
		return fmt.Sprintf("%s:%d|%d %c %s", c.Operand, c.Level, c.Group, c.Operator, c.Next)
	}
	return fmt.Sprintf("%s:%d|%d", c.Operand, c.Level, c.Group)
}

//DebugString formats a ConditionElement to be nicely printed
func (c *ConditionElement) DebugString() string {
	if c.Negate {
		if c.Next != nil {
			return fmt.Sprintf("NOT Operand: %s Operator: (%q) Group:%d Next: (%s)",
				c.Operand, c.Operator, c.Group, c.Next.DebugString())
		}
		return fmt.Sprintf("NOT Operand: %s Operator: (%q) Group:%d Next: nil",
			c.Operand, c.Operator, c.Group)
	}
	if c.Next != nil {
		return fmt.Sprintf("Operand: %s Operator: (%q) Group:%d Next: (%s)",
			c.Operand, c.Operator, c.Group, c.Next.DebugString())

	}
	return fmt.Sprintf("Operand: %s Operator: (%q) Group:%d Next: nil",
		c.Operand, c.Operator, c.Group)
}
