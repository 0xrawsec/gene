package rules

import (
	"encoding/json"
	"fmt"
	"globals"
	"regexp"
	"strings"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
)

var (
	//ErrUnkOperator error to return when an operator is not known
	ErrUnkOperator = fmt.Errorf("Unknown operator")
	//Regexp and its helper to ease AtomRule parsing
	atomRuleRegexp       = regexp.MustCompile(`(?P<name>\$\w+):\s*(?P<operand>(\w+|".*?"))\s*(?P<operator>(=|!=|~=))\s+(?P<value>.*)`)
	atomRuleRegexpHelper = submatch.NewSubmatchHelper(atomRuleRegexp)
)

// AtomRule is the smallest rule we can have
type AtomRule struct {
	Name     string `regexp:"name"`
	Operand  string `regexp:"operand"`
	Operator string `regexp:"operator"`
	Value    string `regexp:"value"`
	compiled bool
	cRule    *regexp.Regexp
}

// ParseAtomRule parses a string and returns an AtomRule
func ParseAtomRule(rule string) (ar AtomRule, err error) {
	sm := atomRuleRegexp.FindSubmatch([]byte(rule))
	err = atomRuleRegexpHelper.Unmarshal(&sm, &ar)
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
	return
}

// NewAtomRule creates a new atomic rule from data
func NewAtomRule(name, operand, operator, value string) AtomRule {
	return AtomRule{name, operand, operator, value, false, nil}
}

func (a *AtomRule) String() string {
	return fmt.Sprintf("%s: %s %s \"%s\"", a.Name, a.Operand, a.Operator, a.Value)
}

// Compile  AtomRule into a regexp
func (a *AtomRule) Compile() {
	var err error
	if !a.compiled {
		switch a.Operator {
		case "=":
			a.cRule, err = regexp.Compile(fmt.Sprintf("(^%s$)", regexp.QuoteMeta(a.Value)))
		/*case "!=":
		a.cRule, err = regexp.Compile(fmt.Sprintf("(%s){0}", regexp.QuoteMeta(a.Value)))
		*/
		case "~=":
			a.cRule, err = regexp.Compile(fmt.Sprintf("(%s)", a.Value))
		}
		a.compiled = true
	}
	if err != nil {
		log.LogError(err)
	}
}

// Utility that converts the operand into a path to search into EVTX
func (a *AtomRule) path() *evtx.GoEvtxPath {
	p := evtx.Path(fmt.Sprintf("/Event/EventData/%s", a.Operand))
	return &p
}

// Match checks whether the AtomRule match the SysmonEvent
func (a *AtomRule) Match(se *evtx.GoEvtxMap) bool {
	s, err := se.GetString(a.path())
	if err == nil {
		a.Compile()
		return a.cRule.MatchString(s)
	}
	return false
}

/////////////////////////////// Tokenizer //////////////////////////////////////

//Tokenizer structure
type Tokenizer struct {
	i        int
	tokens   []string
	expected []string
}

var (
	//EOT End Of Tokens
	EOT = fmt.Errorf("End of tokens")
	//ErrUnexpectedToken definition
	ErrUnexpectedToken = fmt.Errorf("Unexpected tokens")
	EmptyToken         = fmt.Errorf("Empty token")
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
		err = EOT
		return
	}
	for _, token = range t.tokens[t.i:] {
		t.i++
		if token == " " {
			continue
		}
		return
	}
	return "", EOT
}

//NextExpectedToken grabs the next token and returns it. ErrUnexpectedToken is returned
//if the token returned is not in the list of expected tokens
func (t *Tokenizer) NextExpectedToken(expects ...string) (token string, err error) {
	etok := datastructs.NewSyncedSet()
	for _, e := range expects {
		etok.Add(e)
	}
	token, err = t.NextToken()
	if err == EOT {
		return
	}
	log.Debugf("Token: '%s'", token)
	if etok.Contains(token) || etok.Contains(string(token[0])) {
		return
	}
	log.Debugf("%s: '%s' not in %v", ErrUnexpectedToken, token, expects)
	return "", ErrUnexpectedToken
}

func (t *Tokenizer) ParseCondition(group, level int) (c ConditionElement, err error) {
	var token string
	log.Debugf("Tokens: %v", t.tokens[t.i:])

	token, err = t.NextExpectedToken("$", "!", "(", ")", "and", "or")
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
	case EOT:
		// Don't set next element if EOT
		err = nil
	case ErrUnexpectedToken:
		return c, err
	}
	return
}

///////////////////////////////// Condition ////////////////////////////////////

const (
	TypeOperand = 0x1 << iota
	TypeOperator
	TypeNegate
)

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

func Compute(ce *ConditionElement, operands map[string]bool) bool {
	nce, ret := compute(false, ce, operands)
	for nce != nil {
		nce, ret = compute(ret, nce, operands)
	}
	return ret
}

func compute(computed bool, ce *ConditionElement, operands map[string]bool) (*ConditionElement, bool) {
	// Stop Condition
	if ce == nil {
		log.Debug("Any computation should finish here")
		return nil, computed
	}

	switch ce.Type {

	case TypeNegate:
		// Assume next is operand
		if v, ok := operands[ce.Next.Operand]; ok {
			if ce.Next.Level == ce.Level && ce.Next.Group == ce.Group {
				return compute(!v, ce.Next.Next, operands)
			} else {
				nce, v := compute(false, ce.Next, operands)
				return compute(!v, nce, operands)
			}
		} else {
			panic(fmt.Sprintf("Unkown Operand: %s", ce.Next.Operand))
		}
	//!:0|0  $a:1|0  :1|0 | $b:1|0  :0|1 | $a:0|1
	case TypeOperator:
		switch ce.Operator {
		case '&':
			nce, ret := compute(false, ce.Next, operands)
			ret = computed && ret
			return nce, ret
		case '|':
			nce, ret := compute(false, ce.Next, operands)
			ret = computed || ret
			return nce, ret
		}

	case TypeOperand:
		if v, ok := operands[ce.Operand]; ok {
			if ce.Next != nil && ce.Next.Level != ce.Level {
				return ce.Next, v
			}
			return compute(v, ce.Next, operands)
		} else {
			panic(fmt.Sprintf("Unkown Operand: %s", ce.Operand))
		}

	default:
		panic("Unkown type")
	}
	panic("Should not go there")
	return nil, false
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

///////////////////////////////////// Rule /////////////////////////////////////

var (
	defaultCondition = ConditionElement{}
	channelPath      = evtx.Path("/Event/System/Channel")
	computerPath     = evtx.Path("/Event/System/Computer")
)

//CompiledRule definition
type CompiledRule struct {
	Name        string
	Criticality int
	Channels    datastructs.SyncedSet
	Computers   datastructs.SyncedSet
	Tags        datastructs.SyncedSet
	EventIDs    datastructs.SyncedSet
	AtomMap     datastructs.SyncedMap
	Traces      []*Trace
	Conditions  *ConditionElement
}

//NewCompiledRule initializes and returns an EvtxRule object
func NewCompiledRule() (er CompiledRule) {
	er.Tags = datastructs.NewSyncedSet()
	er.Channels = datastructs.NewSyncedSet()
	er.Computers = datastructs.NewSyncedSet()
	er.EventIDs = datastructs.NewSyncedSet()
	er.AtomMap = datastructs.NewSyncedMap()
	return
}

//AddAtom adds an atom rule to the CompiledRule
func (er *CompiledRule) AddAtom(a *AtomRule) {
	er.AtomMap.Add(a.Name, a)
}

func (er *CompiledRule) metaMatch(event *evtx.GoEvtxMap) bool {

	// Handle EventID matching
	if er.EventIDs.Len() > 0 && !er.EventIDs.Contains(event.EventID()) {
		return false
	}

	// Handle channel matching
	if er.Channels.Len() > 0 {
		ch, err := event.GetString(&channelPath)
		if err != nil || !er.Channels.Contains(ch) {
			return false
		}
	}

	// Handle computer matching
	if er.Computers.Len() > 0 {
		comp, err := event.GetString(&computerPath)
		if err != nil || !er.Computers.Contains(comp) {
			return false
		}
	}
	return true
}

//Match returns whether the CompiledRule matches the EVTX event
func (er *CompiledRule) Match(event *evtx.GoEvtxMap) bool {
	if !er.metaMatch(event) {
		return false
	}

	// If there is no rule and the condition is empty we return true
	if *er.Conditions == defaultCondition && er.AtomMap.Len() == 0 {
		return true
	}

	// We proceed with AtomicRule mathing
	log.Debug(er.Conditions)
	return Compute(er.Conditions, er.operandValuesFromAtoms(event))
}

func (er *CompiledRule) operandValuesFromAtoms(event *evtx.GoEvtxMap) map[string]bool {
	operands := make(map[string]bool)
	for operand := range er.AtomMap.Keys() {
		ari, _ := er.AtomMap.Get(operand)
		operands[operand.(string)] = ari.(*AtomRule).Match(event)
	}
	return operands
}

//////////////////////////////// String Rule ///////////////////////////////////
// Temporary: we use JSON for easy parsing right now, lets see if we need to
// switch to another format in the future

//MetaSection defines the section holding the metadata of the rule
type MetaSection struct {
	EventIDs    []int64 // GoEvtxMap.EventID returns int64
	Channels    []string
	Computers   []string
	Traces      []string
	Criticality int
}

//Rule is a JSON parsable rule
type Rule struct {
	Name      string
	Tags      []string
	Meta      MetaSection
	Matches   []string
	Condition string
}

func NewRule() Rule {
	r := Rule{
		Name: "",
		Tags: make([]string, 0),
		Meta: MetaSection{
			EventIDs:    make([]int64, 0),
			Channels:    make([]string, 0),
			Computers:   make([]string, 0),
			Traces:      make([]string, 0),
			Criticality: 0},
		Matches:   make([]string, 0),
		Condition: ""}
	return r
}

//Compile a JSONRule into CompiledRule
func (jr *Rule) Compile() (*CompiledRule, error) {
	var err error
	rule := NewCompiledRule()

	rule.Name = jr.Name
	rule.Criticality = globals.Bound(jr.Meta.Criticality)
	for _, t := range jr.Tags {
		rule.Tags.Add(t)
	}
	// Initializes EventIDs
	for _, e := range jr.Meta.EventIDs {
		rule.EventIDs.Add(e)
	}
	// Initializes Computers
	for _, s := range jr.Meta.Computers {
		rule.Computers.Add(s)
	}
	// Initializes Channels
	for _, s := range jr.Meta.Channels {
		rule.Channels.Add(s)
	}

	// Parses and Initializes the Traces
	for i, st := range jr.Meta.Traces {
		var tr *Trace
		trName := fmt.Sprintf("Trace#%d", i)
		if tr, err = ParseTrace(trName, st); err != nil {
			log.Errorf("Cannot parse trace \"%s\" in \"%s\": %s", st, jr.Name, err)
		} else {
			rule.Traces = append(rule.Traces, tr)
		}
	}

	// Parse predicates
	for _, p := range jr.Matches {
		var a AtomRule
		a, err = ParseAtomRule(p)
		if err != nil {
			log.Errorf("Failed to parse predicate \"%s\": %s", p, err)
			return nil, err
		}
		rule.AddAtom(&a)
	}

	// Parse the condition
	tokenizer := NewTokenizer(jr.Condition)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil && err != EOT {
		log.Errorf("Failed to parse condition \"%s\": %s", jr.Condition, err)
		return nil, err
	}
	rule.Conditions = &cond

	return &rule, nil
}

// Load loads rule to EvtxRule
func Load(b []byte) (*CompiledRule, error) {
	var jr Rule
	err := json.Unmarshal(b, &jr)
	if err != nil {
		return nil, err
	}
	return jr.Compile()
}
