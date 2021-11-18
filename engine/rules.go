package engine

import (
	"encoding/json"
	"fmt"

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

//CompiledRule definition
type CompiledRule struct {
	containers *ContainerDB

	Name        string
	Criticality int
	EventFilter EventFilter
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

//NewCompiledRule initializes and returns an EvtxRule object
func NewCompiledRule(schema Version) (er CompiledRule) {
	er.Tags = datastructs.NewSyncedSet()
	er.Computers = datastructs.NewSyncedSet()
	er.AtomMap = datastructs.NewSyncedMap()
	er.Attack = make([]Attack, 0)
	er.Actions = make([]string, 0)
	er.Schema = schema
	return
}

//AddMatcher adds an atom rule to the CompiledRule
//func (er *CompiledRule) AddMatcher(a *AtomRule) {
func (er *CompiledRule) AddMatcher(m Matcher) {
	er.AtomMap.Add(m.GetName(), m)
}

//SetContainers sets the ContainerDB pointer of rule
func (er *CompiledRule) SetContainers(containers *ContainerDB) {
	er.containers = containers
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

//Match returns whether the CompiledRule matches the EVTX event
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

//MetaSection defines the section holding the metadata of the rule
type MetaSection struct {
	Events      map[string][]int64
	Computers   []string
	Attack      []Attack `json:"ATTACK,omitempty"`
	Criticality int
	Disable     bool
	Filter      bool
	Schema      Version
}

//Rule is a JSON parsable rule
type Rule struct {
	Name      string
	Tags      []string
	Meta      MetaSection
	Matches   []string
	Condition string
	Actions   []string
}

//NewRule creates a new rule used to deserialize from JSON
func NewRule() Rule {
	r := Rule{
		Name: "",
		Tags: make([]string, 0),
		Meta: MetaSection{
			Events:      make(map[string][]int64),
			Computers:   make([]string, 0),
			Attack:      make([]Attack, 0),
			Criticality: 0,
			Schema:      EngineMinimalRuleSchemaVersion},
		Matches:   make([]string, 0),
		Condition: "",
		Actions:   make([]string, 0)}
	return r
}

// IsDisabled returns true if the rule has been disabled
func (jr *Rule) IsDisabled() bool {
	return jr.Meta.Disable
}

//ReplaceTemplate the regexp templates found in the matches
func (jr *Rule) ReplaceTemplate(tm *TemplateMap) {
	for i, match := range jr.Matches {
		jr.Matches[i] = tm.ReplaceAll(match)
	}
}

//JSON returns the JSON string corresponding to the rule
func (jr *Rule) JSON() (string, error) {
	b, err := json.Marshal(jr)
	return string(b), err
}

//Compile a Rule
func (jr *Rule) Compile(e *Engine) (*CompiledRule, error) {
	if e != nil {
		return jr.compile(e.containers)
	}
	return jr.compile(nil)
}

func (jr *Rule) compile(containers *ContainerDB) (*CompiledRule, error) {
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
			a, err = ParseFieldMatch(p)
			if err != nil {
				return nil, err
			}
			rule.AddMatcher(&a)
		case IsContainerMatch(p):
			var cm *ContainerMatch
			cm, err = ParseContainerMatch(p)
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
			return nil, fmt.Errorf("Unknown match statement: %s", p)
		}
	}

	// Parse the condition
	tokenizer := NewTokenizer(jr.Condition)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil && err != ErrEOT {
		return nil, fmt.Errorf("Failed to parse condition \"%s\": %s", jr.Condition, err)
	}

	rule.Conditions = cond
	operands := GetOperands(cond)
	operandsSet := datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(GetOperands(cond))...)
	// We control that all the operands are known
	for _, op := range operands {
		if !rule.AtomMap.Contains(op) {
			return nil, fmt.Errorf("Unkown operand %s in condition \"%s\"", op, jr.Condition)
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

//Load loads rule to EvtxRule
func Load(b []byte, containers *ContainerDB) (*CompiledRule, error) {
	var jr Rule
	err := json.Unmarshal(b, &jr)
	if err != nil {
		return nil, err
	}
	return jr.compile(containers)
}
