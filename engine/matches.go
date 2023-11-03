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
	// ErrSyntax raised when syntax error is met
	ErrSyntax    = fmt.Errorf("syntax error")
	ErrLogFormat = fmt.Errorf("log format error")

	//Regexp and its helper to ease AtomRule parsing
	pathRe                  = `([\w/]+|".*?")`
	fieldMatchRegexp        = regexp.MustCompile(fmt.Sprintf(`(?P<name>\$\w+):\s*(?P<operand>%s)\s*(?P<operator>(=|~=|\&=|<|>|>=|<=))\s+'(?P<value>.*)'`, pathRe))
	fieldMatchRegexpHlpr    = submatch.NewHelper(fieldMatchRegexp)
	indFieldMatchRegexp     = regexp.MustCompile(fmt.Sprintf(`(?P<name>\$\w+):\s*(?P<operand>%s)\s*(?P<operator>=)\s+@(?P<value>%s)`, pathRe, pathRe))
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
	format   *LogType
	path     *XPath
	indPath  *XPath
	cRule    *regexp.Regexp
	iValue   interface{} // interface to store Value in another form as string
}

// IsFieldMatch returns true if s compiliant with FieldMatch syntax
func IsFieldMatch(s string) bool {
	return fieldMatchRegexp.MatchString(s) || indFieldMatchRegexp.MatchString(s)
}

// ParseFieldMatch parses a string and returns a FieldMatch
func ParseFieldMatch(match string, format *LogType) (m FieldMatch, err error) {
	var hlpr submatch.Helper

	// Check if the syntax of the match is valid
	switch {
	case fieldMatchRegexp.Match([]byte(match)):
		hlpr = fieldMatchRegexpHlpr
	case indFieldMatchRegexp.Match([]byte(match)):
		hlpr = indFieldMatchRegexpHlpr
		m.indirect = true
	default:
		return m, fmt.Errorf("%w \"%s\"", ErrSyntax, match)
	}

	// Continues
	hlpr.Prepare([]byte(match))

	err = hlpr.Unmarshal(&m)
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
	m.Operand = strings.Trim(m.Operand, `"'`)
	m.Value = strings.Trim(m.Value, `"'`)
	m.format = format
	// Compile the rule into a Regexp
	err = m.Compile()
	if err != nil {
		log.Debugf("Compiling error in \"%s\": %s", match, err)
		return m, fmt.Errorf("%w: %s", err, match)
	}
	return m, err
}

func parseToFloat(s string) (f float64, err error) {
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return float64(i), err
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, err
	}
	return 0, fmt.Errorf("unknown type to parse")
}

// Compile FieldMatch into a regexp
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
			tmp := Path(f.Value)
			// setting indirect field path
			if IsAbsoluteXPath(f.Value) {
				f.indPath = tmp
			} else if f.format != nil {
				f.indPath = f.format.Data.Merge(tmp)
			} else {
				return fmt.Errorf("%w: either known log format or absolute fields match must be used", ErrLogFormat)
			}
		}

		tmp := Path(f.Operand)
		// setting field path
		if IsAbsoluteXPath(f.Operand) {
			f.path = tmp
		} else if f.format != nil {
			f.path = f.format.Data.Merge(tmp)
		} else {
			return fmt.Errorf("%w: either known log format or absolute fields match must be used", ErrLogFormat)
		}

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
	if err := f.Compile(); err != nil {
		panic(err)
	}

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
	atomContainerMatchRegexp = regexp.MustCompile(fmt.Sprintf(`(?P<name>\$\w+):\s+extract\(\s*'(?P<regexp>.*?\(\?P<(?P<rexname>.*?)>.*?\).*?)'\s*,\s*(?P<operand>%s)\s*\)\s+in\s+(?P<container>[\w\.\-]+)`, pathRe))
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
func ParseContainerMatch(extract string, format *LogType) (cm *ContainerMatch, err error) {
	cm = NewContainerMatch()
	if !atomContainerMatchRegexp.MatchString(extract) {
		return nil, fmt.Errorf("%w \"%s\"", ErrSyntax, extract)
	}
	atomContainerMatchHelper.Prepare([]byte(extract))
	atomContainerMatchHelper.Unmarshal(cm)

	if IsAbsoluteXPath(cm.Operand) {
		cm.path = Path(cm.Operand)
	} else if format != nil {
		cm.path = format.Data.Append(cm.Operand)
	} else {
		return nil, fmt.Errorf("%w: either known log format or absolute fields match must be used", ErrLogFormat)
	}

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
	if err := c.Compile(); err != nil {
		panic(err)
	}

	if extract, ok := c.Extract(evt); ok {
		log.Debugf("checking if extracted=%s in=%s", extract, c.Container)
		if c.containerDB != nil {
			res := c.containerDB.ContainsString(c.Container, extract)
			log.Debugf("result=%t", res)
			return res
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
