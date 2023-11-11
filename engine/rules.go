package engine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
	"gopkg.in/yaml.v3"
)

///////////////////////////////////// Rule /////////////////////////////////////

var (
	defaultCondition = ConditionElement{}
)

const (
	SeverityBound = 10
)

func boundSeverity(sev int) int {
	if sev >= SeverityBound {
		return SeverityBound
	}
	return sev
}

// CompiledRule definition
type CompiledRule struct {
	containers *ContainerDB

	Name        string
	Severity    int
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
}

// NewCompiledRule initializes and returns an EvtxRule object
func NewCompiledRule() (er CompiledRule) {
	er.Tags = datastructs.NewSyncedSet()
	er.OSs = datastructs.NewSyncedSet()
	er.Computers = datastructs.NewSyncedSet()
	er.AtomMap = datastructs.NewSyncedMap()
	er.Attack = make([]Attack, 0)
	er.Actions = make([]string, 0)
	return
}

// AddMatcher adds an atom rule to the CompiledRule
// func (er *CompiledRule) AddMatcher(a *AtomRule) {
func (er *CompiledRule) AddMatcher(m matcher) {
	er.AtomMap.Add(m.getName(), m)
}

// setContainers sets the ContainerDB pointer of rule
func (er *CompiledRule) setContainers(containers *ContainerDB) {
	er.containers = containers
}

// matchOS checks if os is suitable for this rule
func (er *CompiledRule) matchOS(os string) bool {
	if er.OSs.Len() == 0 {
		return true
	}
	return er.OSs.Contains(os)
}

func (er *CompiledRule) matchStep1(evt Event) bool {
	// rule must be enabled and EventFilter must match event
	return !er.Disabled && er.EventFilter.Match(evt)
}

// matchStep2 only checks if condition is matching
func (er *CompiledRule) matchStep2(evt Event) bool {
	// Handle computer matching
	if er.Computers.Len() > 0 {
		if comp := evt.Computer(); !er.Computers.Contains(comp) {
			return false
		}
	}

	// If there is no rule and the condition is empty we return true
	if *er.Conditions == defaultCondition && er.AtomMap.Len() == 0 {
		return true
	}

	// We proceed with AtomicRule mathing
	return Compute(er.Conditions, er.operandReader(evt))
}

// Match returns whether the CompiledRule matches the event
func (er *CompiledRule) Match(evt Event) bool {
	// both the steps must be true so that match is a success
	return er.matchStep1(evt) && er.matchStep2(evt)
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
		return ari.(matcher).match(oe.event), true
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
	ErrInvalidOS        = fmt.Errorf("invalid OS")
	ErrInvalidFieldName = fmt.Errorf("invalid field name")
	ErrInvalidMatch     = fmt.Errorf("invalid match statement")
	ErrUnknownOperand   = fmt.Errorf("unknown operand")
	ErrLogTypeNotSet    = fmt.Errorf("log type not set or ambiguous")
)

// Attack structure definiton to encode information from ATT&CK Mitre
type Attack struct {
	ID          string `yaml:"id" json:"id,omitempty"`
	Tactic      string `yaml:"tactic" json:"tactic,omitempty"`
	Description string `yaml:"description,omitempty" json:",omitempty"`
	Reference   string `yaml:"reference,omitempty"`
}

// MetaSection defines the section holding the metadata of the rule
type MetaSection struct {
	Attack   []Attack `yaml:"attack,omitempty" json:"ATTACK,omitempty"`
	Authors  []string `yaml:"authors,omitempty"`
	Comments []string `yaml:"comments,omitempty"`
}

type Params struct {
	Disable bool `yaml:"disable,omitempty"`
	Filter  bool `yaml:"filter,omitempty"`
}

type MatchOn struct {
	LogType   string             `yaml:"log-type,omitempty"`
	Events    map[string][]int64 `yaml:"events,omitempty"`
	OSs       []string           `yaml:"oss,omitempty"`
	Computers []string           `yaml:"computers,omitempty"`
}

// Rule is a JSON parsable rule
type Rule struct {
	Name      string            `yaml:"name"`
	Tags      []string          `yaml:"tags,omitempty"`
	Meta      MetaSection       `yaml:"meta,omitempty"`
	Params    Params            `yaml:"params,omitempty"`
	MatchOn   MatchOn           `yaml:"match-on,omitempty"`
	Matches   map[string]string `yaml:"matches,omitempty"`
	Condition string            `yaml:"condition,omitempty"`
	Severity  int               `yaml:"severity,omitempty"`
	Actions   []string          `yaml:"actions,omitempty"`
}

type Decoder interface {
	Decode(v interface{}) error
}

func jsonRuleDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec
}

func yamlRuleDecoder(r io.Reader) Decoder {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	return dec
}

// NewRule creates a new rule used to deserialize from JSON
func NewRule() Rule {
	r := Rule{
		Name: "",
		Tags: make([]string, 0),
		MatchOn: MatchOn{
			Events:    make(map[string][]int64),
			OSs:       make([]string, 0),
			Computers: make([]string, 0),
		},
		Meta: MetaSection{
			Attack: make([]Attack, 0),
		},
		Matches:   make(map[string]string),
		Condition: "",
		Severity:  0,
		Actions:   make([]string, 0)}
	return r
}

// IsDisabled returns true if the rule has been disabled
func (r *Rule) IsDisabled() bool {
	return r.Params.Disable
}

// ReplaceTemplate the regexp templates found in the matches
func (r *Rule) ReplaceTemplate(tm *TemplateMap) {
	for name, match := range r.Matches {
		r.Matches[name] = tm.ReplaceAll(match)
	}
}

// Json returns the Json string corresponding to the rule
func (r *Rule) Json() (string, error) {
	b, err := json.Marshal(r)
	return string(b), err
}

// JSON returns the JSON string corresponding to the rule
func (r *Rule) Yaml() (string, error) {
	b, err := yaml.Marshal(r)
	return string(b), err
}

func (r *Rule) resolveLogType(logTypes map[string]*LogType) *LogType {
	// the logtype specified in rule takes precedence
	if len(r.MatchOn.LogType) > 0 {
		return logTypes[r.MatchOn.LogType]
	}

	// if we wanna match ONLY kunai events
	if _, ok := r.MatchOn.Events["kunai"]; ok && len(r.MatchOn.Events) == 1 {
		return logTypes["kunai"]
	}

	// based on windows channels frequently matched
	winMatch := 0
	for c := range r.MatchOn.Events {
		if c == "Security" ||
			c == "Application" ||
			c == "System" ||
			strings.HasPrefix(c, "Microsoft") ||
			strings.HasPrefix(c, "Windows") {
			winMatch += 1
		}
	}

	// we are sure ONLY all we want to match are windows channels
	if winMatch == len(r.MatchOn.Events) {
		return logTypes["winevt"]
	}

	return nil
}

// Compile a Rule
func (r *Rule) Compile(e *Engine) (*CompiledRule, error) {
	if e != nil {
		return r.compile(e.containers, r.resolveLogType(e.logTypes))
	}
	return r.compile(nil, nil)
}

func (r *Rule) compile(containers *ContainerDB, logType *LogType) (*CompiledRule, error) {
	var err error
	rule := NewCompiledRule()

	rule.Name = r.Name
	rule.Severity = boundSeverity(r.Severity)
	// Pass ATT&CK information to compiled rule
	rule.Attack = r.Meta.Attack
	// Pass Actions to compiled rule
	rule.Actions = r.Actions
	for _, t := range r.Tags {
		rule.Tags.Add(t)
	}

	// Setting up event filter
	if len(r.MatchOn.Events) > 0 && logType == nil {
		return nil, fmt.Errorf("cannot use match-on events: %w", ErrLogTypeNotSet)
	}
	rule.EventFilter = NewEventFilter(r.MatchOn.Events)

	// Initializes OSs
	for _, os := range r.MatchOn.OSs {
		// force OS being lower case
		os = strings.ToLower(os)
		if !supportedOS.Contains(os) {
			return nil, fmt.Errorf("%w os=%s", ErrInvalidOS, os)
		}
		rule.OSs.Add(os)
	}

	// Initializes Computers
	if len(r.MatchOn.Computers) > 0 && logType == nil {
		return nil, fmt.Errorf("cannot use match-on computers: %w", ErrLogTypeNotSet)
	}
	for _, s := range r.MatchOn.Computers {
		rule.Computers.Add(s)
	}

	// Set Filter member
	rule.Filter = r.Params.Filter

	// Parse predicates
	for mname, p := range r.Matches {
		if !isValidName(mname) {
			return nil, fmt.Errorf("%w name=%s", ErrInvalidFieldName, mname)
		}

		switch {
		case isFieldMatch(p):
			var a FieldMatch
			a, err = parseFieldMatch(mname, p, logType)
			if err != nil {
				return nil, err
			}
			rule.AddMatcher(&a)
		case isContainerMatch(p):
			var cm *ContainerMatch
			cm, err = parseContainerMatch(mname, p, logType)
			if err != nil {
				return nil, err
			}
			//Set the rules containers only if the rule contains at least ContainerMatch
			rule.containers = containers
			if rule.containers != nil {
				if !rule.containers.Has(cm.Container) {
					Logger.Warnf("Unknown container \"%s\" used in rule \"%s\"", cm.Container, rule.Name)
					rule.Disabled = true
					Logger.Warnf("Rule \"%s\" has been disabled at compile time", rule.Name)
					return &rule, nil
				}
			} else {
				Logger.Warnf("Unknown container \"%s\" used in rule \"%s\"", cm.Container, rule.Name)
				rule.Disabled = true
				Logger.Warnf("Rule \"%s\" has been disabled at compile time", rule.Name)
				return &rule, nil
			}
			cm.setContainerDB(rule.containers)
			rule.AddMatcher(cm)
		default:
			return nil, fmt.Errorf("%w match=%s", ErrInvalidMatch, p)
		}
	}

	// Parse the condition
	tokenizer := NewTokenizer(r.Condition)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil && err != ErrEOT {
		return nil, fmt.Errorf("%w condition=%s", err, r.Condition)
	}

	rule.Conditions = cond
	operands := GetOperands(cond)
	operandsSet := datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(GetOperands(cond))...)
	// We control that all the operands are known
	for _, op := range operands {
		if !rule.AtomMap.Contains(op) {
			return nil, fmt.Errorf("%w operand=%s", ErrUnknownOperand, op)
		}
	}

	// Check for unknown operands and display warnings
	for _, iOp := range rule.AtomMap.Keys() {
		if !operandsSet.Contains(iOp.(string)) {
			Logger.Warnf("Rule \"%s\" operand %s not used", rule.Name, iOp.(string))
		}
	}
	return &rule, nil
}

// loadJsonRule loads (unmarshal and compile) a rule
func loadJsonRule(b []byte, containers *ContainerDB) (*CompiledRule, error) {
	var r Rule

	dec := jsonRuleDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&r)
	if err != nil {
		return nil, err
	}
	return r.compile(containers, r.resolveLogType(logTypes))
}

// loadJsonRule loads (unmarshal and compile) a rule
func loadYamlRule(b []byte, containers *ContainerDB) (*CompiledRule, error) {
	var r Rule

	dec := yamlRuleDecoder(bytes.NewBuffer(b))
	err := dec.Decode(&r)
	if err != nil {
		return nil, err
	}
	return r.compile(containers, r.resolveLogType(logTypes))
}
