package engine

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"globals"
	"io"
	"os"
	"rules"
	"sync"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
)

var (
	geneInfoPath = evtx.Path("/Event/GeneInfo")
)

// generates a random string that can be used as rulename
func randRuleName() string {
	var b [32]byte
	rand.Read(b[:])
	return data.Md5(b[:])
}

//ErrRuleExist definition
type ErrRuleExist struct {
	ruleName string
}

//Error error implementation
func (e ErrRuleExist) Error() string {
	return fmt.Sprintf("Rule \"%s\" already exists", e.ruleName)
}

//Engine defines the engine managing several rules
type Engine struct {
	sync.RWMutex
	rules    []*rules.CompiledRule
	tags     map[string][]int // will be map[tag][]int with index referencing rule in rules
	names    map[string]int   // will be map[name][]int with index referencing rule in rules
	channels map[string][]int
	eventIDs map[int64][]int
	// Filters used to choose which rule to compile if case of match by tag/name
	tagFilters  datastructs.SyncedSet
	nameFilters datastructs.SyncedSet
	trace       bool
	// Used to mark the traces and not duplicate those
	markedTraces datastructs.SyncedSet
}

//NewEngine creates a new engine
func NewEngine(trace bool) (e Engine) {
	e.rules = make([]*rules.CompiledRule, 0)
	e.tags = make(map[string][]int)
	e.names = make(map[string]int)
	e.channels = make(map[string][]int)
	e.eventIDs = make(map[int64][]int)
	e.tagFilters = datastructs.NewSyncedSet()
	e.nameFilters = datastructs.NewSyncedSet()
	e.trace = trace
	e.markedTraces = datastructs.NewSyncedSet()
	return
}

func (e *Engine) SetFilters(names, tags []string) {
	for _, n := range names {
		e.nameFilters.Add(n)
	}
	for _, t := range tags {
		e.tagFilters.Add(t)
	}
}

//Count returns the number of rules successfuly loaded
func (e *Engine) Count() int {
	return len(e.rules)
}

func (e *Engine) loadReader(reader io.Reader) error {
	dec := json.NewDecoder(reader)
	for {
		var jRule rules.Rule
		if err := dec.Decode(&jRule); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		er, err := jRule.Compile()
		if err != nil {
			return err
		}
		if err := e.AddRule(er); err != nil {
			return err
		}
	}
	return nil

}

func (e *Engine) LoadReader(reader io.Reader) error {
	return e.loadReader(reader)
}

//Load loads a rule file into the current engine
func (e *Engine) Load(rulefile string) error {
	f, err := os.Open(rulefile)
	if err != nil {
		return err
	}
	return e.loadReader(f)
	/*
		dec := json.NewDecoder(f)
		for {
			var jRule rules.Rule
			if err := dec.Decode(&jRule); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			er, err := jRule.Compile()
			if err != nil {
				return err
			}
			if err := e.AddRule(er); err != nil {
				return err
			}
		}
		return nil*/
}

//AddRule adds a rule to the current engine
func (e *Engine) AddRule(r *rules.CompiledRule) error {
	// We skip adding the rule to the engine if we decided to match by name(s)
	if !e.nameFilters.Contains(r.Name) && e.nameFilters.Len() > 0 {
		log.Debugf("Skip compiling by name %s", r.Name)
		return nil
	}
	// We skip adding the rule to the engine if we decided to match by tags
	if e.tagFilters.Intersect(&(r.Tags)).Len() == 0 && e.tagFilters.Len() > 0 {
		log.Debugf("Skip compiling by tags %s", r.Name)
		return nil
	}
	return e.addRule(r, r.Name)
}

// addRule adds a rule r to the engine, k is the key used in the map to store
// the rule
func (e *Engine) addRule(r *rules.CompiledRule, k string) error {
	e.Lock()
	defer e.Unlock()
	// don't need to increment since element will be appended at i
	i := len(e.rules)
	if _, ok := e.names[k]; ok {
		return ErrRuleExist{k}
	}
	e.rules = append(e.rules, r)
	e.names[k] = i

	// Update the map of tags in order to speed up search by tag
	for _, t := range *(r.Tags.List()) {
		key := t.(string)
		e.tags[key] = append(e.tags[key], i)
	}

	// Update the map of channels
	for _, c := range *(r.Channels.List()) {
		key := c.(string)
		e.channels[key] = append(e.channels[key], i)
	}

	// Update the map of eventIDs
	for _, eid := range *(r.EventIDs.List()) {
		key := eid.(int64)
		e.eventIDs[key] = append(e.eventIDs[key], i)
	}

	return nil
}

func (e *Engine) AddTraceRules(ruleList ...*rules.CompiledRule) {
	for _, r := range ruleList {
		if err := e.addRule(r, randRuleName()); err != nil {
			log.Errorf("Cannot add rule \"%s\": %s", r.Name, err)
		}
	}
}

//Match checks if there is a match in any rule of the engine
func (e *Engine) Match(event *evtx.GoEvtxMap) (names []string, criticality int) {
	traces := make([]*rules.CompiledRule, 0)
	names = make([]string, 0)

	e.RLock()
	for _, r := range e.rules {
		if r.Match(event) {
			names = append(names, r.Name)
			criticality += r.Criticality
			// If we decide to trace the other events matching the rules
			if e.trace {
				for i, tr := range r.Traces {
					value, err := event.GetString(tr.Path())
					// If we find the appropriate element in the event we matched
					if err == nil {
						// Hashing the trace
						h := tr.HashWithValue(value)
						if !e.markedTraces.Contains(h) {
							// We add the hash of the current trace not to recompile it again
							e.markedTraces.Add(h)
							// We compile the trace into a rule and append it to the list of traces
							if tRule, err := tr.Compile(r, value); err == nil {
								traces = append(traces, tRule)
							} else {
								log.Errorf("Failed to compile trace rule i=%d for \"%s\" ", i, r.Name)
							}
						}
					}
				}
			}
		}
	}
	// Unlock so that we can update engine
	e.RUnlock()

	// We can update with the traces since we released the lock
	e.AddTraceRules(traces...)

	// Bound criticality
	criticality = globals.Bound(criticality)
	// Update event with signature information
	genInfo := map[string]interface{}{
		"Signature":   names,
		"Criticality": criticality}
	event.Set(&geneInfoPath, genInfo)
	return
}
