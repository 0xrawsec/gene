package engine

import (
	"github.com/0xrawsec/golang-utils/datastructs"
)

type EventFilter map[string]*datastructs.Set

func NewEventFilter(m map[string][]int64) EventFilter {
	f := make(EventFilter)
	for channel, eventids := range m {
		f[channel] = datastructs.NewSet()
		for _, eventid := range eventids {
			f[channel].Add(eventid)
		}
	}
	return f
}

func (f EventFilter) match(source string, id int64) bool {
	// if there is no filter we match by default
	if f.IsEmpty() {
		return true
	}

	if eventids, ok := f[source]; ok {
		if eventids.Len() > 0 {
			return eventids.Contains(id)
		}
		return true
	}

	return false
}

func (f EventFilter) IsEmpty() bool {
	return len(f) == 0
}

func (f EventFilter) Match(e Event) bool {
	return f.match(e.Channel(), e.EventID())
}
