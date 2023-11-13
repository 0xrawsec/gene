package engine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

func TestEvent(t *testing.T) {
	var evt GenericEvent

	tt := toast.FromT(t)

	tt.CheckErr(json.Unmarshal([]byte(eventStr), &evt))

	tt.Assert(evt.Source() == "Microsoft-Windows-Sysmon/Operational")
	t.Log(evt.Computer())
	tt.Assert(evt.Computer() == "DESKTOP-5SUA567")
	ts, err := time.Parse(time.RFC3339Nano, "2017-01-19T16:09:30Z")
	tt.CheckErr(err)
	tt.Assert(evt.Timestamp().Equal(ts))

	// detection must be nil
	d, ok := evt.GetDetection()
	tt.Assert(!ok && d == nil)
	det := NewMatchResult(true, true, CamelCase)
	evt.SetDetection(det)
	d, ok = evt.GetDetection()
	tt.Assert(d == det && ok)

}
