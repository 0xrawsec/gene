package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
)

///////////////////////////////////// Rule /////////////////////////////////////

var (
	defaultCondition = ConditionElement{}
)

const (
	CriticalityBound = 10
)

func bound(i int) int {
	if i >= CriticalityBound {
		return CriticalityBound
	}
	return i
}

// CompiledRule definition
type CompiledRule struct {
	containers *ContainerDB

	Name        string
	Criticality int
	EventFilter EventFilter
	OSs         *datastructs.SyncedSet
	Computers   *datastructs.SyncedSet
	Tags        *datastructs.SyncedSet
	AtomMap     *datastructs.SyncedMap
	Disabled    bool // Way to deal with no container issue
	Filter      bool // whether it is a Filter rule or not
	Conditions  *ConditionElement
	Actions     []string
	// ATT&CK information
	Attack []Attack
	Schema Version
}

// NewCompiledRule initializes and returns an EvtxRule object
func NewCompiledRule(schema Version) (er CompiledRule) {
	er.Tags = datastructs.NewSyncedSet()
	er.OSs = datastructs.NewSyncedSet()
	er.Computers = datastructs.NewSyncedSet()
	er.AtomMap = datastructs.NewSyncedMap()
	er.Attack = make([]Attack, 0)
	er.Actions = make([]string, 0)
	er.Schema = schema
	return
}

// AddMatcher adds an atom rule to the CompiledRule
// func (er *CompiledRule) AddMatcher(a *AtomRule) {
func (er *CompiledRule) AddMatcher(m Matcher) {
	er.AtomMap.Add(m.GetName(), m)
}

// SetContainers sets the ContainerDB pointer of rule
func (er *CompiledRule) SetContainers(containers *ContainerDB) {
	er.containers = containers
}

// matchOS checks if the is able suitable for OS passed as parameter
func (er *CompiledRule) matchOS(os string) bool {
	if er.OSs.Len() == 0 {
		return true
	}
	return er.OSs.Contains(os)
}

func (er *CompiledRule) metaMatch(evt Event) bool {

	if !er.EventFilter.Match(evt) {
		return false
	}

	// Handle computer matching
	if er.Computers.Len() > 0 {
		if comp := evt.Computer(); !er.Computers.Contains(comp) {
			return false
		}
	}
	return true
}

// Match returns whether the CompiledRule matches the EVTX event
func (er *CompiledRule) Match(evt Event) bool {
	// Check if the rule is disabled, if yes match returns false
	if er.Disabled {
		return false
	}

	if !er.metaMatch(evt) {
		return false
	}

	// If there is no rule and the condition is empty we return true
	if *er.Conditions == defaultCondition && er.AtomMap.Len() == 0 {
		return true
	}

	// We proceed with AtomicRule mathing
	log.Debug(er.Conditions)
	return Compute(er.Conditions, er.operandReader(evt))
}

func (er *CompiledRule) operandReader(evt Event) *EventOpReader {
	return &EventOpReader{evt, er}
}

//////////////////////////// EventOpStore /////////////////////////////////////

// EventOpReader OperandReader interface to access operand value of a rule on an event
type EventOpReader struct {
	event Event
	rule  *CompiledRule
}

// Read OperandStore interface definition
func (oe *EventOpReader) Read(operand string) (value bool, ok bool) {
	if ari, ok := oe.rule.AtomMap.Get(operand); ok {
		// Casting to Matcher interface
		return ari.(Matcher).Match(oe.event), true
	}
	return
}

//////////////////////////////// String Rule ///////////////////////////////////
// Temporary: we use JSON for easy parsing right now, lets see if we need to
// switch to another format in the future

var supportedOS = datastructs.NewInitSyncedSet(
	"aix",
	"android",
	"darwin",
	"dragonfly",
	"freebsd",
	"illumos",
	"ios",
	"js",
	"linux",
	"netbsd",
	"openbsd",
	"plan9",
	"solaris",
	"wasip1",
	"windows",
)

var (
	ErrInvalidOS = fmt.Errorf("invalid OS")
)

// MetaSection defines the section holding the metadata of the rule
type MetaSection struct {
	LogType     string
	Events      map[string][]int64
	OSs         []string
	Computers   []string
	Attack      []Attack `json:"ATTACK,omitempty"`
	Criticality int
	Disable     bool
	Filter      bool
	Schema      Version
}

// Rule is a JSON parsable rule
type Rule struct {
	Name      string
	Tags      []string
	Meta      MetaSection
	Matches   []string
	Condition string
	Actions   []string
}

func NewRuleDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec
}

// NewRule creates a new rule used to deserialize from JSON
func NewRule() Rule {
	r := Rule{
		Name: "",
		Tags: make([]string, 0),
		Meta: MetaSection{
			Events:      make(map[string][]int64),
			OSs:         make([]string, 0),
			Computers:   make([]string, 0),
			Attack:      make([]Attack, 0),
			Criticality: 0,
			Schema:      EngineMinimalRuleSchemaVersion,
		},
		Matches:   make([]string, 0),
		Condition: "",
		Actions:   make([]string, 0)}
	return r
}

// IsDisabled returns true if the rule has been disabled
func (jr *Rule) IsDisabled() bool {
	return jr.Meta.Disable
}

// ReplaceTemplate the regexp templates found in the matches
func (jr *Rule) ReplaceTemplate(tm *TemplateMap) {
	for i, match := range jr.Matches {
		jr.Matches[i] = tm.ReplaceAll(match)
	}
}

// JSON returns the JSON string corresponding to the rule
func (jr *Rule) JSON() (string, error) {
	b, err := json.Marshal(jr)
	return string(b), err
}

// Compile a Rule
func (jr *Rule) Compile(e *Engine) (*CompiledRule, error) {
	if e != nil {
		return jr.compile(e.containers, e.logFormats[jr.Meta.LogType])
	}
	return jr.compile(nil, nil)
}

func (jr *Rule) compile(containers *ContainerDB, format *LogType) (*CompiledRule, error) {
	var err error
	rule := NewCompiledRule(jr.Meta.Schema)

	rule.Name = jr.Name
	rule.Criticality = bound(jr.Meta.Criticality)
	// Pass ATT&CK information to compiled rule
	rule.Attack = jr.Meta.Attack
	// Pass Actions to compiled rule
	rule.Actions = jr.Actions
	for _, t := range jr.Tags {
		rule.Tags.Add(t)
	}

	// Setting up event filter
	rule.EventFilter = NewEventFilter(jr.Meta.Events)

	// Initializes OSs
	for _, os := range jr.Meta.OSs {
		// force OS being lower case
		os = strings.ToLower(os)
		if !supportedOS.Contains(os) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidOS, os)
		}
		rule.OSs.Add(os)
	}

	// Initializes Computers
	for _, s := range jr.Meta.Computers {
		rule.Computers.Add(s)
	}

	// Set Filter member
	rule.Filter = jr.Meta.Filter

	// Parse predicates
	for _, p := range jr.Matches {
		switch {
		case IsFieldMatch(p):
			var a FieldMatch
			a, err = ParseFieldMatch(p, format)
			if err != nil {
				return nil, err
			}
			rule.AddMatcher(&a)
		case IsContainerMatch(p):
			var cm *ContainerMatch
			cm, err = ParseContainerMatch(p, format)
			if err != nil {
				return nil, err
			}
			//Set the rules containers only if the rule contains at least ContainerMatch
			rule.containers = containers
			if rule.containers != nil {
				if !rule.containers.Has(cm.Container) {
					log.Warnf("Unknown container \"%s\" used in rule \"%s\"", cm.Container, rule.Name)
					rule.Disabled = true
					log.Warnf("Rule \"%s\" has been disabled at compile time", rule.Name)
					return &rule, nil
				}
			} else {
				log.Warnf("Unknown container \"%s\" used in rule \"%s\"", cm.Container, rule.Name)
				rule.Disabled = true
				log.Warnf("Rule \"%s\" has been disabled at compile time", rule.Name)
				return &rule, nil
			}
			cm.SetContainerDB(rule.containers)
			rule.AddMatcher(cm)
		default:
			return nil, fmt.Errorf("unknown match statement: %s", p)
		}
	}

	// Parse the condition
	tokenizer := NewTokenizer(jr.Condition)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil && err != ErrEOT {
		return nil, fmt.Errorf("failed to parse condition \"%s\": %s", jr.Condition, err)
	}

	rule.Conditions = cond
	operands := GetOperands(cond)
	operandsSet := datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(GetOperands(cond))...)
	// We control that all the operands are known
	for _, op := range operands {
		if !rule.AtomMap.Contains(op) {
			return nil, fmt.Errorf("unkown operand %s in condition \"%s\"", op, jr.Condition)
		}
	}

	// Check for unknown operands and display warnings
	for _, iOp := range rule.AtomMap.Keys() {
		if !operandsSet.Contains(iOp.(string)) {
			log.Warnf("Rule \"%s\" operand %s not used", rule.Name, iOp.(string))
		}
	}
	return &rule, nil
}

// LoadRule loads (unmarshal and compile) a rule
func LoadRule(b []byte, containers *ContainerDB, format *LogType) (*CompiledRule, error) {
	var jr Rule

	dec := NewRuleDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&jr)
	if err != nil {
		return nil, err
	}
	return jr.compile(containers, format)
}
