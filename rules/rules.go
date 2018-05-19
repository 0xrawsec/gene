package rules

import (
	"encoding/json"
	"fmt"
	"globals"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
)

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
	Disabled    bool // Way to deal with no container issue
	Conditions  *ConditionElement
	containers  *ContainerDB
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

//AddMatcher adds an atom rule to the CompiledRule
//func (er *CompiledRule) AddMatcher(a *AtomRule) {
func (er *CompiledRule) AddMatcher(m Matcher) {
	er.AtomMap.Add(m.GetName(), m)
}

//SetContainers sets the ContainerDB pointer of rule
func (er *CompiledRule) SetContainers(containers *ContainerDB) {
	er.containers = containers
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
	// Check if the rule is disabled, if yes match returns false
	if er.Disabled {
		return false
	}

	if !er.metaMatch(event) {
		return false
	}

	// If there is no rule and the condition is empty we return true
	if *er.Conditions == defaultCondition && er.AtomMap.Len() == 0 {
		return true
	}

	// We proceed with AtomicRule mathing
	log.Debug(er.Conditions)
	return Compute(er.Conditions, er.operandReader(event))
}

func (er *CompiledRule) operandReader(event *evtx.GoEvtxMap) *EventOpReader {
	return &EventOpReader{event, er}
}

//////////////////////////// EventOpStore /////////////////////////////////////

// EventOpReader OperandReader interface to access operand value of a rule on an event
type EventOpReader struct {
	event *evtx.GoEvtxMap
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
	EventIDs    []int64 // GoEvtxMap.EventID returns int64
	Channels    []string
	Computers   []string
	Traces      []string
	Criticality int
	Disable     bool
}

//Rule is a JSON parsable rule
type Rule struct {
	Name      string
	Tags      []string
	Meta      MetaSection
	Matches   []string
	Condition string
}

//NewRule creates a new rule used to deserialize from JSON
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

//Compile a JSONRule into CompiledRule
func (jr *Rule) Compile(containers *ContainerDB) (*CompiledRule, error) {
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
			return nil, fmt.Errorf("Cannot parse trace \"%s\" in \"%s\": %s", st, jr.Name, err)
		}
		rule.Traces = append(rule.Traces, tr)
	}

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

	rule.Conditions = &cond
	operands := GetOperands(&cond)
	operandsSet := datastructs.NewInitSyncedSet(datastructs.ToInterfaceSlice(GetOperands(&cond))...)
	// We control that all the operands are known
	for _, op := range operands {
		if !rule.AtomMap.Contains(op) {
			return nil, fmt.Errorf("Unkown operand %s in condition \"%s\"", op, jr.Condition)
		}
	}

	// Check for unknown operands and display warnings
	for iOp := range rule.AtomMap.Keys() {
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
	return jr.Compile(containers)
}
