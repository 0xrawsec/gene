package engine

import "testing"

func TestPath(t *testing.T) {
	empty := Path("")
	edata := Path("/Event/EventData")
	edataCp := Path("/Event/EventData")
	udata := Path("/Event/UserData")
	procid := Path("/Event/EventData/ProcessId")

	// testing equality
	if !edata.Equal(edataCp) {
		t.Errorf("%s and %s should be equal", edata, edataCp)
	}

	if edata.Equal(udata) {
		t.Errorf("%s and %s should not be equal", edata, udata)
	}

	if !procid.StartsWith(edata) {
		t.Errorf("%s should start with %s", procid, edata)
	}

	if empty.StartsWith(edata) {
		t.Errorf("empty path should not start with %s", edata)
	}

	if procid.Last() != "ProcessId" {
		t.Errorf("Wrong last element")
	}
}
