package engine

import "github.com/0xrawsec/golang-utils/datastructs"

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

func (f EventFilter) Match(e Event) bool {
	// if there is no filter we match by default
	if len(f) == 0 {
		return true
	}

	if eventids, ok := f[e.Channel()]; ok {
		if eventids.Len() > 0 {
			return eventids.Contains(e.EventID())
		}
		return true
	}

	return false
}
