package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
)

// Matcher interface
type Matcher interface {
	GetName() string
	Match(*evtx.GoEvtxMap) bool
}

var (
	//ErrUnkOperator error to return when an operator is not known
	ErrUnkOperator = fmt.Errorf("Unknown operator")
	//Regexp and its helper to ease AtomRule parsing
	fieldMatchRegexp       = regexp.MustCompile(`(?P<name>\$\w+):\s*(?P<operand>(\w+|".*?"))\s*(?P<operator>(=|~=))\s+'(?P<value>.*)'`)
	fieldMatchRegexpHelper = submatch.NewSubmatchHelper(fieldMatchRegexp)
)

// FieldMatch is the smallest rule we can have
type FieldMatch struct {
	Name     string `regexp:"name"`
	Operand  string `regexp:"operand"`
	Operator string `regexp:"operator"`
	Value    string `regexp:"value"`
	compiled bool
	path     *evtx.GoEvtxPath
	cRule    *regexp.Regexp
}

// IsFieldMatch returns true if s compiliant with FieldMatch syntax
func IsFieldMatch(s string) bool {
	return fieldMatchRegexp.MatchString(s)
}

// ParseFieldMatch parses a string and returns an FieldMatch
func ParseFieldMatch(rule string) (ar FieldMatch, err error) {
	// Check if the syntax of the match is valid
	if !fieldMatchRegexp.Match([]byte(rule)) {
		return ar, fmt.Errorf("Syntax error in \"%s\"", rule)
	}
	// Continues
	sm := fieldMatchRegexp.FindSubmatch([]byte(rule))
	err = fieldMatchRegexpHelper.Unmarshal(&sm, &ar)
	// it is normal not to set private fields
	if fse, ok := err.(submatch.FieldNotSetError); ok {
		switch fse.Field {
		case "compiled", "cRule":
			err = nil
		}
	}
	if err != nil {
		return
	}
	ar.Operand = strings.Trim(ar.Operand, `"'`)
	ar.Value = strings.Trim(ar.Value, `"'`)
	// Compile the rule into a Regexp
	err = ar.Compile()
	if err != nil {
		return ar, fmt.Errorf("Failed to compile \"%s\" to a regexp", rule)
	}
	return ar, err
}

// NewFieldMatch creates a new FieldMatch rule from data
func NewFieldMatch(name, operand, operator, value string) *FieldMatch {
	return &FieldMatch{name, operand, operator, value, false, nil, nil}
}

// Compile  AtomRule into a regexp
func (f *FieldMatch) Compile() error {
	var err error
	if !f.compiled {
		switch f.Operator {
		case "=":
			f.cRule, err = regexp.Compile(fmt.Sprintf("(^%s$)", regexp.QuoteMeta(f.Value)))
		case "~=":
			f.cRule, err = regexp.Compile(fmt.Sprintf("(%s)", f.Value))
		}
		p := evtx.Path(fmt.Sprintf("/Event/EventData/%s", f.Operand))
		f.path = &p
		f.compiled = true
	}
	if err != nil {
		return err
	}
	return nil
}

// GetName implements Matcher interface
func (f *FieldMatch) GetName() string {
	return f.Name
}

// Match checks whether the AtomRule match the SysmonEvent
func (f *FieldMatch) Match(se *evtx.GoEvtxMap) bool {
	//s, err := se.GetString(a.path())
	f.Compile()
	s, err := se.GetString(f.path)
	if err == nil {
		return f.cRule.MatchString(s)
	}
	return false
}

func (f *FieldMatch) String() string {
	return fmt.Sprintf("%s: %s %s \"%s\"", f.Name, f.Operand, f.Operator, f.Value)
}

////////////////////////////// ContainerMatch ///////////////////////////////

var (
	atomContainerMatchRegexp = regexp.MustCompile(`(?P<name>\$\w+):\s+extract\(\s*'(?P<regexp>.*?\(\?P<(?P<rexname>.*?)>.*?\).*?)'\s*,\s*(?P<operand>.*)\s*\)\s+in\s+(?P<container>\w+)`)
	atomContainerMatchHelper = submatch.NewSubmatchHelper(atomContainerMatchRegexp)
)

// ContainerMatch atomic extract structure
type ContainerMatch struct {
	Name           string `regexp:"name"`
	RexName        string `regexp:"rexname"`
	Regexp         string `regexp:"regexp"`
	Operand        string `regexp:"operand"`
	Container      string `regexp:"container"`
	path           *evtx.GoEvtxPath
	compiled       bool
	subMatchHelper *submatch.SubmatchHelper
	cExtract       *regexp.Regexp
	containerDB    *ContainerDB
}

// ParseContainerMatch parses an extract and returns an AtomExtract from it
func ParseContainerMatch(extract string) (ae *ContainerMatch, err error) {
	ae = NewContainerMatch()
	if !atomContainerMatchRegexp.MatchString(extract) {
		return nil, fmt.Errorf("Syntax error in \"%s\"", extract)
	}
	sm := atomContainerMatchRegexp.FindSubmatch([]byte(extract))
	atomContainerMatchHelper.Unmarshal(&sm, ae)
	// We prepend with a dolar so that it is complient with the syntax already defined
	p := evtx.Path(fmt.Sprintf("/Event/EventData/%s", ae.Operand))
	ae.path = &p
	return
}

// IsContainerMatch returns true if match is compliant with ContainerMatch syntax
func IsContainerMatch(s string) bool {
	return atomContainerMatchRegexp.MatchString(s)
}

// NewContainerMatch creates a new ContainerMatch structure
func NewContainerMatch() *ContainerMatch {
	ae := &ContainerMatch{}

	ae.containerDB = NewContainers()
	return ae
}

// SetContainerDB sets the containerDB member
func (c *ContainerMatch) SetContainerDB(db *ContainerDB) {
	c.containerDB = db
}

// Compile compiles an AtomExtract, any AtomExtract must be compiled before use
func (c *ContainerMatch) Compile() (err error) {
	if !c.compiled {
		c.cExtract, err = regexp.Compile(c.Regexp)
		if err == nil {
			smh := submatch.NewSubmatchHelper(c.cExtract)
			c.subMatchHelper = &smh
		}
		c.compiled = true
	}
	return err
}

// ExtractFromString uses the AtomExtract to extract a substring from s
func (c *ContainerMatch) ExtractFromString(s string) (string, bool) {
	sm := c.cExtract.FindSubmatch([]byte(s))
	extract, err := c.subMatchHelper.GetBytes(c.RexName, &sm)
	if err == nil {
		return string(extract), true
	}
	return "", false
}

// Extract uses the AtomExtract to extract a substring from a value of a Windows Event
func (c *ContainerMatch) Extract(ev *evtx.GoEvtxMap) (string, bool) {
	if field, err := ev.GetString(c.path); err == nil {
		return c.ExtractFromString(field)
	}
	return "", false
}

// Match matches the extract rule against a ContainerDB and implements Matcher interface
func (c *ContainerMatch) Match(ev *evtx.GoEvtxMap) bool {
	c.Compile()
	if extract, ok := c.Extract(ev); ok {
		log.Debugf("Extracted: %s", extract)
		if c.containerDB != nil {
			return c.containerDB.Contains(c.Container, extract)
		}
	}
	return false
}

// GetName implements Matcher interface
func (c *ContainerMatch) GetName() string {
	return c.Name
}

func (c *ContainerMatch) String() string {
	return fmt.Sprintf("Name: %s, Regexp: %s, Operand: %s, Container: %s", c.RexName, c.Regexp, c.Operand, c.Container)
}
