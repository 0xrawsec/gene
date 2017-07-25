package engine

import (
	"encoding/json"
	"fmt"
	"globals"
	"io"
	"os"
	"rules"
	"sync"

	"github.com/0xrawsec/golang-evtx/evtx"
)

var (
	geneInfoPath = evtx.Path("/Event/GeneInfo")
)

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
}

//NewEngine creates a new engine
func NewEngine() (e Engine) {
	e.rules = make([]*rules.CompiledRule, 0)
	e.tags = make(map[string][]int)
	e.names = make(map[string]int)
	e.channels = make(map[string][]int)
	e.eventIDs = make(map[int64][]int)
	return
}

//Count returns the number of rules successfuly loaded
func (e *Engine) Count() int {
	return len(e.rules)
}

//Load loads a rule file into the current engine
func (e *Engine) Load(rulefile string) error {
	f, err := os.Open(rulefile)
	if err != nil {
		return err
	}
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
	return nil
}

//AddRule adds a rule to the current engine
func (e *Engine) AddRule(r *rules.CompiledRule) error {
	e.Lock()
	defer e.Unlock()
	// don't need to increment since element will be appended at i
	i := len(e.rules)
	if _, ok := e.names[r.Name]; ok {
		return ErrRuleExist{r.Name}
	}
	e.rules = append(e.rules, r)
	e.names[r.Name] = i

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

//Match checks if there is a match in any rule of the engine
func (e *Engine) Match(event *evtx.GoEvtxMap) (names []string, criticality int) {
	e.RLock()
	defer e.RUnlock()
	names = make([]string, 0)
	for _, r := range e.rules {
		if r.Match(event) {
			names = append(names, r.Name)
			criticality += r.Criticality
		}
	}

	// Bound criticality
	criticality = globals.Bound(criticality)
	// Update event with signature information
	genInfo := map[string]interface{}{
		"Signature":   names,
		"Criticality": criticality}
	event.Set(&geneInfoPath, genInfo)
	return
}

//MatchByTag checks if any tagged rules matches the event
func (e *Engine) MatchByTag(tags *[]string, event *evtx.GoEvtxMap) (names []string, criticality int) {
	e.RLock()
	defer e.RUnlock()
	names = make([]string, 0)
	for _, t := range *tags {
		if rIndexes, ok := e.tags[t]; ok {
			for _, rIdx := range rIndexes {
				r := e.rules[rIdx]
				if r.Match(event) {
					names = append(names, r.Name)
					criticality += r.Criticality
				}
			}
		}
	}

	// Bound criticality
	criticality = globals.Bound(criticality)
	// Update event with signature information
	genInfo := map[string]interface{}{
		"Signature":   names,
		"Criticality": criticality}
	event.Set(&geneInfoPath, genInfo)
	return
}

//MatchByName checks if rule referenced by name in the engine matches the event
func (e *Engine) MatchByName(name string, event *evtx.GoEvtxMap) (bool, int) {
	e.RLock()
	defer e.RUnlock()
	if rIdx, ok := e.names[name]; ok {
		r := e.rules[rIdx]
		if r.Match(event) {
			// Bound criticality
			criticality := globals.Bound(r.Criticality)
			// Update event with signature information
			genInfo := map[string]interface{}{
				"Signature":   []string{name},
				"Criticality": criticality}
			event.Set(&geneInfoPath, genInfo)
			return true, r.Criticality
		}
	}
	return false, 0
}
