package engine

import "testing"

func TestFilter(t *testing.T) {
	f0 := NewEventFilter(map[string][]int64{
		"Microsoft-Windows-Sysmon/Operational": {},
	})

	f1 := NewEventFilter(map[string][]int64{
		"Microsoft-Windows-Sysmon/Operational": {1, 2, 3, 4, 5},
	})

	if !f0.Match(&winevtEvent) {
		t.Errorf("Filter should match event")
	}

	if !f1.Match(&winevtEvent) {
		t.Errorf("Filter should match event")
	}
}
