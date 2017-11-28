package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/crypto/data"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
)

const (
	sep = ","
)

var (
	traceRE       = regexp.MustCompile(`^(?P<eventids>([0-9,]*)|(any|ANY|\*)):(?P<channels>[^:.]*):\s*(?P<operand>\w+)\s+(?P<operator>(=|~=))\s+(?P<value>\w+)$`)
	traceREHelper = submatch.NewSubmatchHelper(traceRE)
)

type stringTrace struct {
	EventIDs string `regexp:"eventids"`
	Channels string `regexp:"channels"`
	Operator string `regexp:"operator"`
	Operand  string `regexp:"operand"`
	Value    string `regexp:"value"`
}

func ParseTrace(name, trace string) (*Trace, error) {
	return parseTrace(name, trace)
}

func parseTrace(name, trace string) (*Trace, error) {
	st := stringTrace{}
	c := NewTrace(name)
	if !traceRE.MatchString(trace) {
		return nil, fmt.Errorf("Invalid trace syntax")
	}
	sm := traceRE.FindSubmatch([]byte(trace))
	if err := traceREHelper.Unmarshal(&sm, &st); err != nil {
		log.Debug(err)
		return nil, err
	}

	// Parsing the EventIDs
	switch st.EventIDs {
	case "any", "ANY", "*":
		c.anyEventID = true
	default:
		if st.EventIDs != "" {
			strEventIDs := strings.Split(st.EventIDs, sep)
			for _, seid := range strEventIDs {
				eid, err := strconv.ParseInt(seid, 10, 64)
				if err != nil {
					return nil, err
				}
				c.EventIDs = append(c.EventIDs, eid)
			}
		}
	}

	// Parsing the Channels
	switch st.Channels {
	case "any", "ANY":
		c.anyChannel = true
	default:
		if st.Channels != "" {
			c.Channels = strings.Split(st.Channels, sep)
		}
	}

	c.Operand = st.Operand
	c.Operator = st.Operator
	c.Value = st.Value

	return c, nil
}

type Trace struct {
	Name       string
	EventIDs   []int64
	Channels   []string
	Operand    string
	Operator   string
	Value      string
	anyEventID bool
	anyChannel bool
}

func NewTrace(name string) *Trace {
	c := Trace{}
	c.Name = name
	c.EventIDs = make([]int64, 0)
	c.Channels = make([]string, 0)
	return &c
}

func (t *Trace) idStr() string {
	return fmt.Sprintf("%v:%v:%v:%s:%s:%s:%t:%t", t.EventIDs, t.Channels, t.Operand,
		t.Operator, t.Value, t.anyChannel, t.anyChannel)
}

func (t *Trace) Hash() string {
	return data.Md5([]byte(t.idStr()))
}

func (t *Trace) HashWithValue(value string) string {
	return data.Md5([]byte(fmt.Sprintf("%s:%s", t.idStr(), value)))
}

func (t *Trace) Path() *evtx.GoEvtxPath {
	p := evtx.Path(fmt.Sprintf("/Event/EventData/%s", t.Value))
	return &p
}

func (t *Trace) Compile(trigger *CompiledRule, value string) (*CompiledRule, error) {
	cr := NewCompiledRule()

	// Define the name of the compiled rule
	cr.Name = fmt.Sprintf("%s%s", trigger.Name, t.Name)

	// Propagate the tags of the trigger
	cr.Tags = datastructs.NewSyncedSet(&(trigger.Tags))

	// Updating the EventIDs
	if !t.anyEventID {
		for _, eid := range t.EventIDs {
			cr.EventIDs.Add(eid)
		}
		// If there is no EventID in the trace, we take the ones of the triggering rule
		if len(t.EventIDs) == 0 {
			cr.EventIDs = datastructs.NewSyncedSet(&(trigger.EventIDs))
		}
	}

	// Updating the Channels
	if !t.anyChannel {
		for _, channel := range t.Channels {
			cr.Channels.Add(channel)
		}
		// If there is no Channel in the trace, we take the ones of the triggering rule
		if cr.Channels.Len() == 0 {
			cr.Channels = datastructs.NewSyncedSet(&(trigger.Channels))
		}
	}

	// Propagate the Computers fields of the trigger
	cr.Computers = datastructs.NewSyncedSet(&(trigger.Computers))

	// Propagate the Criticality of the trigger
	cr.Criticality = trigger.Criticality

	cr.Traces = trigger.Traces

	// Create a simple atom
	a := NewAtomRule("$a", t.Operand, t.Operator, value)
	cr.AddAtom(&a)

	// Create the condition only matching the atom previously created
	cr.Conditions = NewCondGroup(&Condition{Operand: "$a"})

	return &cr, nil
}
