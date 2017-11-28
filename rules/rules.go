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
		case "!=":
			a.cRule, err = regexp.Compile(fmt.Sprintf("(%s){0}", regexp.QuoteMeta(a.Value)))
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
			}
			if token[len(token)-1] == ')' {
				c.tokens[i] = token[:len(token)-1]
				c.tokens = append(c.tokens[:i+1], append([]string{")"}, c.tokens[i+1:]...)...)
			}
		}
	}
	log.Debug(c.tokens)
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

//ParseCondition parses a condition
func (t *Tokenizer) ParseCondition(group, level int) (c Condition, err error) {
	var token string

	token, err = t.NextExpectedToken("$", "!", "(", ")", "and", "or")
	if err != nil {
		return
	}
BeginSwitch:
	switch token[0] {
	case '!':
		c.Negate = true
		token = token[1:]
		goto BeginSwitch
	case '$':
		// Set the operand
		c.Operand = token
		// Set the Level
		c.Level = level
		c.Group = group
		token, err = t.NextExpectedToken("and", "&&", "AND", "or", "||", "OR", ")")
		//if err != nil && err == ErrUnexpectedToken {
		if err != nil {
			return
		}
		// Set the operator according to the operator
		switch token {
		case "and", "&&", "AND":
			c.Operator = '&'
		case "or", "||", "OR":
			c.Operator = '|'
		case ")":
			group++
			level--
			token, err = t.NextExpectedToken("and", "&&", "AND", "or", "||", "OR", ")")
			if err != nil {
				return
			}
			switch token {
			case "and", "&&", "AND":
				c.Operator = '&'
			case "or", "||", "OR":
				c.Operator = '|'
			}
		}
		// Set the next condition
		next, err := t.ParseCondition(group, level)
		switch err {
		case nil, EOT:
			c.Next = &next
		case ErrUnexpectedToken:
			return c, err
		}
	case '(':
		level++

		if len(token) > 1 {
			token = token[1:]
			goto BeginSwitch
		} else {
			return t.ParseCondition(group, level)
		}
	}
	return
}

///////////////////////////////// Condition ////////////////////////////////////

//Condition structure definition
type Condition struct {
	Operand  string
	Operator rune
	Negate   bool
	Level    int
	Group    int
	Next     *Condition
}

func (c *Condition) String() string {
	if c.Negate {
		//return fmt.Sprintf("NOT Operand: %s Operator: (%q) Level:%d Next: (%s)",
		//c.Operand, c.Operator, c.Level, c.Next)
		if c.Next != nil {
			return fmt.Sprintf("!%s %c %s", c.Operand, c.Operator, c.Next)
		}
		return fmt.Sprintf("!%s", c.Operand)
	}
	//return fmt.Sprintf("Operand: %s Operator: (%q) Level:%d Next: (%s)",
	//c.Operand, c.Operator, c.Level, c.Next)
	if c.Next != nil {
		return fmt.Sprintf("%s %c %s", c.Operand, c.Operator, c.Next)
	}
	return fmt.Sprintf("%s", c.Operand)
}

func (c *Condition) DebugString() string {
	if c.Negate {
		//return fmt.Sprintf("NOT Operand: %s Operator: (%q) Level:%d Next: (%s)",
		//c.Operand, c.Operator, c.Level, c.Next)
		return fmt.Sprintf("NOT Operand: %s Operator: (%q) Group:%d Next: (%s)",
			c.Operand, c.Operator, c.Group, c.Next.DebugString())
	}
	//return fmt.Sprintf("Operand: %s Operator: (%q) Level:%d Next: (%s)",
	//c.Operand, c.Operator, c.Level, c.Next)
	return fmt.Sprintf("Operand: %s Operator: (%q) Group:%d Next: (%s)",
		c.Operand, c.Operator, c.Group, c.Next.DebugString())
}

////////////////////////////// Group ///////////////////////////////////////////

type CondGroup struct {
	condition    *Condition
	operatorSub  rune
	subGroup     *CondGroup
	operatorNext rune
	next         *CondGroup
}

func (cg *CondGroup) String() string {
	return fmt.Sprintf("condition:%s\noperatorSub:(%q)\nsubgroup:%s\noperatorNext:(%q)\nnext=%s\n",
		cg.condition, cg.operatorSub, cg.subGroup, cg.operatorNext, cg.next)
}

func NewCondGroup(condition *Condition) *CondGroup {
	group := CondGroup{}
	group.condition = condition
	if condition != nil {
		for cond := condition; cond.Next != nil; cond = cond.Next {
			log.Debug(condition)
			log.Debug(condition.Next)
			if cond.Next.Level > cond.Level {
				group.subGroup = NewCondGroup(cond.Next)
				group.operatorSub = cond.Operator
				cond.Next = nil
				break
			} else if cond.Next.Level <= cond.Level && cond.Next.Group != cond.Group {
				group.next = NewCondGroup(cond.Next)
				group.operatorNext = cond.Operator
				cond.Next = nil
				break
			}
		}
	}
	return &group
}

///////////////////////////////////// Rule /////////////////////////////////////

var (
	defaultCondition = Condition{}
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
	//Condition   *Condition
	Conditions *CondGroup
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

func (er *CompiledRule) matchGroup(group *CondGroup, event *evtx.GoEvtxMap) bool {
	// Match the condition
	mc := er.matchCondition(group.condition, event)
	log.Debugf("Match Condition: %s Result: %t", group.condition, mc)
	// Match subgroup equal to condition match by default
	result := mc
	// Then match any subgroup
	if group.subGroup != nil {
		switch {
		case !mc && group.operatorSub == '&':
			result = false
			break
		case mc && group.operatorSub == '|':
			result = true
			break
		default:
			switch group.operatorSub {
			case '&':
				result = mc && er.matchGroup(group.subGroup, event)
			case '|':
				result = mc || er.matchGroup(group.subGroup, event)
			default:
				panic(ErrUnkOperator)
			}
		}
	}

	if group.next != nil {
		switch group.operatorNext {
		case '&':
			if !result {
				return result
			}
			ngm := er.matchGroup(group.next, event)
			return result && ngm
		case '|':
			if result {
				return result
			}
			ngm := er.matchGroup(group.next, event)
			return result || ngm
		default:
			panic(ErrUnkOperator)
		}
	}
	// If no more group we return the value of msg
	return result
}

func (er *CompiledRule) matchCondition(cond *Condition, event *evtx.GoEvtxMap) bool {
	if a, ok := er.AtomMap.Contains(cond.Operand); ok {
		// If there is not other continuation in the condition
		if cond.Next == nil {
			am := a.(*AtomRule).Match(event)
			log.Debugf("Testing:%s Result:%t", a.(*AtomRule), am)
			if cond.Negate {
				log.Debugf("Return:%t", !am)
				return !am
			}
			log.Debugf("Return:%t", am)
			return am
		}

		switch cond.Operator {
		case '&':
			am := a.(*AtomRule).Match(event)
			log.Debugf("Testing:%s Result:%t", a.(*AtomRule), am)
			//log.Debugf("MatchNext:%t Cond.Next:%s", er.match(cond.Next, event), cond.Next)
			nm := er.matchCondition(cond.Next, event)
			if cond.Negate {
				log.Debugf("Return:%t", !am && nm)
				return !am && nm
			}
			log.Debugf("Return:%t", am && nm)
			return am && nm
		case '|':
			am := a.(*AtomRule).Match(event)
			log.Debugf("Testing:%s Result:%t", a.(*AtomRule), am)
			//log.Debugf("MatchNext:%t Cond.Next:%s", er.match(cond.Next, event), cond.Next)
			nm := er.matchCondition(cond.Next, event)
			if cond.Negate {
				log.Debugf("Return:%t", !am || nm)
				return !am || nm
			}
			log.Debugf("Return:%t", am || nm)
			return am || nm
		default:
			//case '\x00':
			am := a.(*AtomRule).Match(event)
			log.Debugf("Testing:%s Result:%t", a.(*AtomRule), am)
			if cond.Negate {
				log.Debugf("Return:%t", !am)
				return !am
			}
			log.Debugf("Return:%t", am)
			return am
		}
	} else {
		log.Errorf("Unknown Operand: %s", cond.Operand)
		return false
	}
}

//Match returns whether the CompiledRule matches the EVTX event
func (er *CompiledRule) Match(event *evtx.GoEvtxMap) bool {
	if !er.metaMatch(event) {
		return false
	}

	// If there is no rule and the condition is empty we return true
	if *(er.Conditions.condition) == defaultCondition && er.AtomMap.Len() == 0 {
		return true
	}

	// We proceed with AtomicRule mathing
	//return er.matchCondition(er.Condition, event)
	log.Debug(er.Conditions)
	return er.matchGroup(er.Conditions, event)
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
	//rule.Condition = &cond
	rule.Conditions = NewCondGroup(&cond)

	return &rule, nil
}

// Load loads rule to EvtxRule
func Load(b []byte) (*CompiledRule, error) {
	var jr Rule
	//rule := NewCompiledRule()
	err := json.Unmarshal(b, &jr)
	if err != nil {
		return nil, err
	}
	return jr.Compile()
}
