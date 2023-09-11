package engine

import (
	"testing"

	"github.com/0xrawsec/toast"
)

var (
	someEventData = Path("/Event/EventData/ProcessId")
	someUserData  = Path("/Event/UserData/FieldXYZ")

	benchIterations = 100000
)

func TestPath(t *testing.T) {
	tt := toast.FromT(t)

	empty := Path("")
	edata := Path("/Event/EventData")
	edataCp := Path("/Event/EventData")
	udata := Path("/Event/UserData")
	procid := Path("/Event/EventData/ProcessId")

	tt.Assert(edata.Equal(edataCp))
	tt.Assert(!edata.Equal(udata))
	tt.Assert(procid.StartsWith(edata))
	tt.Assert(!empty.StartsWith(edata))
	tt.Assert(procid.Last() == "ProcessId")

	tt.Assert(procid.Get(0) == "Event")
	tt.Assert(procid.Get(1) == "EventData")
	tt.Assert(procid.Get(2) == "ProcessId")
	tt.Assert(procid.Get(3) == "")
	tt.Assert(procid.Get(-1) == "")

	tt.Assert(edata.Len() == 2)
	tt.Assert(procid.Len() == 3)

	tt.Assert(edata.String() == "/Event/EventData")
	tt.Assert(procid.String() == "/Event/EventData/ProcessId")

	tt.Assert(IsAbsoluteXPath("/Event/EventData"))
	tt.Assert(!IsAbsoluteXPath("ProcessId"))
}

func TestJoin(t *testing.T) {
	tt := toast.FromT(t)

	p := Path("/Event").Append("EventData")

	tt.Assert(p.Flags.EventDataField)
	tt.Assert(p.Equal(Path("/Event/EventData")))

}

func BenchmarkPathStartsWith(b *testing.B) {
	for i := 0; i < benchIterations; i++ {
		if !someEventData.StartsWith(eventDataPath) {
			b.FailNow()
		}
		if someUserData.StartsWith(eventDataPath) {
			b.FailNow()
		}
	}
}

func BenchmarkPathIsEventData(b *testing.B) {
	for i := 0; i < benchIterations; i++ {
		if !someEventData.Flags.EventDataField {
			b.FailNow()
		}
		if !someUserData.Flags.UserDataField {
			b.FailNow()
		}
	}
}
