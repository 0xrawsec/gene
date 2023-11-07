package engine

import (
	"encoding/json"
	"fmt"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/jsonobj"
)

type MatchResult struct {
	Signature     *datastructs.Set
	Severity      int
	ATTACK        []Attack         `json:",omitempty"`
	Actions       *datastructs.Set `json:",omitempty"`
	attackIds     *datastructs.Set
	filtered      bool
	fieldNameConv NameConv
}

func (m *MatchResult) MarshalJSON() ([]byte, error) {
	o := jsonobj.New()

	switch m.fieldNameConv {
	case SnakeCase:
		// snake case cannot be reverted back to structure
		// if json fields name are not set to camel case
		o.Options.FieldNameConvention = jsonobj.LowerCase
	case CamelCase:
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnkNameConv, m.fieldNameConv)
	}

	o.SetField("Signature", m.Signature)
	o.SetField("Severity", m.Severity)
	if m.HasAttack() {
		o.SetField("ATTACK", o.ConvertSlice(m.ATTACK))
	}
	if m.HasActions() {
		o.SetField("Actions", m.Actions)
	}

	return json.Marshal(o)
}

func NewMatchResult(attack, action bool, fieldNameConv NameConv) *MatchResult {
	var att []Attack

	var act, attIds *datastructs.Set

	if attack {
		att = make([]Attack, 0)
		attIds = datastructs.NewSet()
	}

	if action {
		act = datastructs.NewSet()
	}

	return &MatchResult{
		Signature:     datastructs.NewSet(),
		ATTACK:        att,
		Actions:       act,
		attackIds:     attIds,
		fieldNameConv: fieldNameConv,
	}
}

func (m *MatchResult) HasActions() bool {
	if m.Actions == nil {
		return false
	}
	return m.Actions.Len() > 0
}

func (m *MatchResult) HasAttack() bool {
	if m.ATTACK == nil {
		return false
	}
	return len(m.ATTACK) > 0
}

func (m *MatchResult) Update(r *CompiledRule) {
	if r.Filter {
		m.filtered = true
		return
	}

	// updating severity information
	if r.Severity+m.Severity > 10 {
		m.Severity = 10
	} else {
		m.Severity += r.Severity
	}

	// updating attack information
	if m.ATTACK != nil {
		for _, a := range r.Attack {
			// if attack id is not already there
			if !m.attackIds.Contains(a.ID) {
				m.ATTACK = append(m.ATTACK, a)
				m.attackIds.Add(a.ID)
			}
		}
	}

	// updating actions
	if m.Actions != nil {
		m.Actions.Add(datastructs.ToInterfaceSlice(r.Actions)...)
	}

	// signature information
	m.Signature.Add(r.Name)
}

// MatchCount returns the number of matches
func (m *MatchResult) MatchCount() int {
	return m.Signature.Len()
}

// MatchesSlice returns the names of the rules which matched the event
func (m *MatchResult) MatchesSlice() []string {
	n := make([]string, m.Signature.Len())
	for i, in := range m.Signature.Slice() {
		n[i] = in.(string)
	}
	return n
}

// IsDetection returns true if it is a detection
func (m *MatchResult) IsDetection() bool {
	return m.Signature.Len() > 0
}

// IsFiltered returns true if it is filter
func (m *MatchResult) IsFiltered() bool {
	return m.filtered
}

// IsEmpty returns true if MatchResult neither is a detection nor a filter
func (m *MatchResult) IsEmpty() bool {
	return m.Signature.Len() == 0 && !m.filtered
}

// IsOnlyFiltered tells that the event only matched filter rules
// this is similar to !IsDetection() && IsFiltered()
func (m *MatchResult) IsOnlyFiltered() bool {
	return m.filtered && m.Signature.Len() == 0
}
