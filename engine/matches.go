package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
)

// Matcher interface
type Matcher interface {
	GetName() string
	Match(Event) bool
}

var (
	//ErrUnkOperator error to return when an operator is not known
	ErrUnkOperator = fmt.Errorf("Unknown operator")
	//Regexp and its helper to ease AtomRule parsing
	fieldMatchRegexp        = regexp.MustCompile(`(?P<name>\$\w+):\s*(?P<operand>(\w+|".*?"))\s*(?P<operator>(=|~=|\&=|<|>|>=|<=))\s+'(?P<value>.*)'`)
	fieldMatchRegexpHlpr    = submatch.NewHelper(fieldMatchRegexp)
	indFieldMatchRegexp     = regexp.MustCompile(`(?P<name>\$\w+):\s*(?P<operand>(\w+|".*?"))\s*(?P<operator>=)\s+@(?P<value>.*)`)
	indFieldMatchRegexpHlpr = submatch.NewHelper(indFieldMatchRegexp)
)

// FieldMatch is the smallest rule we can have
type FieldMatch struct {
	Name     string `regexp:"name"`
	Operand  string `regexp:"operand"`
	Operator string `regexp:"operator"`
	Value    string `regexp:"value"`
	indirect bool
	compiled bool
	path     *XPath
	indPath  *XPath
	cRule    *regexp.Regexp
	iValue   interface{} // interface to store Value in another form as string
}

// IsFieldMatch returns true if s compiliant with FieldMatch syntax
func IsFieldMatch(s string) bool {
	return fieldMatchRegexp.MatchString(s) || indFieldMatchRegexp.MatchString(s)
}

// ParseFieldMatch parses a string and returns an FieldMatch
func ParseFieldMatch(rule string) (ar FieldMatch, err error) {
	var hlpr submatch.Helper

	// Check if the syntax of the match is valid
	switch {
	case fieldMatchRegexp.Match([]byte(rule)):
		hlpr = fieldMatchRegexpHlpr
	case indFieldMatchRegexp.Match([]byte(rule)):
		hlpr = indFieldMatchRegexpHlpr
		ar.indirect = true
	default:
		return ar, fmt.Errorf("Syntax error in \"%s\"", rule)
	}

	// Continues
	hlpr.Prepare([]byte(rule))

	err = hlpr.Unmarshal(&ar)
	// it is normal not to set private fields
	if fse, ok := err.(submatch.FieldNotSetError); ok {
		switch fse.Field {
		case "compiled", "cRule", "indirect":
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
		log.Debugf("Compiling error in \"%s\": %s", rule, err)
		return ar, fmt.Errorf("Failed to compile \"%s\"", rule)
	}
	return ar, err
}

// NewFieldMatch creates a new FieldMatch rule from data
func NewFieldMatch(name, operand, operator, value string) *FieldMatch {
	return &FieldMatch{name, operand, operator, value, false, false, nil, nil, nil, 0}
}

func parseToFloat(s string) (f float64, err error) {
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return float64(i), err
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, err
	}
	return 0, fmt.Errorf("Unknown type to parse")
}

// Compile  AtomRule into a regexp
func (f *FieldMatch) Compile() error {
	var err error
	if !f.compiled {
		if !f.indirect {
			switch f.Operator {
			case "=":
				f.cRule, err = regexp.Compile(fmt.Sprintf("(^%s$)", regexp.QuoteMeta(f.Value)))
			case "~=":
				f.cRule, err = regexp.Compile(fmt.Sprintf("(%s)", f.Value))
			case "&=":
				f.iValue, err = strconv.ParseInt(f.Value, 0, 64)
			case ">", "<", ">=", "<=":
				f.iValue, err = parseToFloat(f.Value)
			}
		} else {
			p := Path(fmt.Sprintf("/Event/EventData/%s", f.Value))
			f.indPath = p
		}
		p := Path(fmt.Sprintf("/Event/EventData/%s", f.Operand))
		f.path = p
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
func (f *FieldMatch) Match(se Event) bool {
	f.Compile()
	s, ok := EventGetString(se, f.path)
	if ok {
		// indirect match means we compare with the value of another field
		if f.indirect {
			if is, ok := EventGetString(se, f.indPath); ok {
				return is == s
			}
		} else {
			switch f.Operator {
			case "&=":
				// This operator treats values as integers
				rValue, err := strconv.ParseInt(s, 0, 64)
				if err != nil {
					return false
				}
				flag := f.iValue.(int64)
				if (flag & rValue) == flag {
					return true
				}

			case ">", "<", "<=", ">=":
				// This operator treats values as floats
				rValue, err := parseToFloat(s)
				if err != nil {
					return false
				}

				switch f.Operator {
				case ">":
					return rValue > f.iValue.(float64)
				case ">=":
					return rValue >= f.iValue.(float64)
				case "<":
					return rValue < f.iValue.(float64)
				case "<=":
					return rValue <= f.iValue.(float64)
				}
			default:
				return f.cRule.MatchString(s)
			}
		}
	}
	return false
}

func (f *FieldMatch) String() string {
	return fmt.Sprintf("%s: %s %s \"%s\"", f.Name, f.Operand, f.Operator, f.Value)
}

////////////////////////////// ContainerMatch ///////////////////////////////

var (
	atomContainerMatchRegexp = regexp.MustCompile(`(?P<name>\$\w+):\s+extract\(\s*'(?P<regexp>.*?\(\?P<(?P<rexname>.*?)>.*?\).*?)'\s*,\s*(?P<operand>.*)\s*\)\s+in\s+(?P<container>[\w\.\-]+)`)
	atomContainerMatchHelper = submatch.NewHelper(atomContainerMatchRegexp)
)

// ContainerMatch atomic extract structure
type ContainerMatch struct {
	Name           string `regexp:"name"`
	RexName        string `regexp:"rexname"`
	Regexp         string `regexp:"regexp"`
	Operand        string `regexp:"operand"`
	Container      string `regexp:"container"`
	path           *XPath
	compiled       bool
	subMatchHelper *submatch.Helper
	cExtract       *regexp.Regexp
	containerDB    *ContainerDB
}

// ParseContainerMatch parses an extract and returns an AtomExtract from it
func ParseContainerMatch(extract string) (ae *ContainerMatch, err error) {
	ae = NewContainerMatch()
	if !atomContainerMatchRegexp.MatchString(extract) {
		return nil, fmt.Errorf("Syntax error in \"%s\"", extract)
	}
	atomContainerMatchHelper.Prepare([]byte(extract))
	atomContainerMatchHelper.Unmarshal(ae)
	// We prepend with a dolar so that it is complient with the syntax already defined
	p := Path(fmt.Sprintf("/Event/EventData/%s", ae.Operand))
	ae.path = p
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
			smh := submatch.NewHelper(c.cExtract)
			c.subMatchHelper = &smh
		}
		c.compiled = true
	}
	return err
}

// ExtractFromString uses the AtomExtract to extract a substring from s
func (c *ContainerMatch) ExtractFromString(s string) (string, bool) {
	c.subMatchHelper.Prepare([]byte(s))
	extract, err := c.subMatchHelper.GetBytes(c.RexName)
	if err == nil {
		return string(extract), true
	}
	return "", false
}

// Extract uses the AtomExtract to extract a substring from a value of a Windows Event
func (c *ContainerMatch) Extract(evt Event) (string, bool) {
	if field, ok := EventGetString(evt, c.path); ok {
		return c.ExtractFromString(field)
	}
	return "", false
}

// Match matches the extract rule against a ContainerDB and implements
// Matcher interface the string matched against the container are converted
// to lower case (default behaviour of ContainsString method)
func (c *ContainerMatch) Match(evt Event) bool {
	c.Compile()
	if extract, ok := c.Extract(evt); ok {
		log.Debugf("Extracted: %s", extract)
		if c.containerDB != nil {
			return c.containerDB.ContainsString(c.Container, extract)
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
