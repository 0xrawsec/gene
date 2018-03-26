package main

import (
	"encoding/json"
	"engine"
	"fmt"
	"rules"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

func init() {
	//log.InitLogger(log.LDebug)
}

func ToJSON(data interface{}) []byte {
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	traces = []string{
		"::ProcessGuid = ProcessGuid",
		"1::ProcessGuid = ProcessGuid",
		"1,2,4:foo/channel:ProcessGuid = ProcessGuid",
		"1,2,5,6:foo-test/channel,bar-test/channel:ProcessGuid = ProcessGuid",
	}

	triggerRule = `{
	"Name": "Test",
	"Tags": ["Hello", "World"],
	"Meta": {
		"EventIDs": [1,7],
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"Computers": [],
		"Criticality": 10,
    "Traces": [
  		"::ProcessGuid = ProcessGuid",
  		"1::ProcessGuid = ProcessGuid",
  		"1,2,4:foo/channel:ProcessGuid = ProcessGuid",
  		"1,2,5,4624:foo-test/channel,bar-test/channel:ProcessGuid = ProcessGuid"
      ]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA256=9C55962723810A23130E40BBA8A28907408D04A046F8E044863729F3924BCB37'"
		],
	"Condition": "$a"
	}`

	trigger, _ = rules.Load([]byte(triggerRule), nil)
)

func TestParseTrace(t *testing.T) {
	for i, st := range traces {
		trName := fmt.Sprintf("Trace#%d", i)
		if tr, err := rules.ParseTrace(trName, st); err != nil {
			t.Log(err)
			t.Fail()
		} else {
			t.Log(string(ToJSON(tr)))
		}
	}
}

func TestCompileTrace(t *testing.T) {
	for i, st := range traces {
		trName := fmt.Sprintf("Trace#%d", i)
		if tr, err := rules.ParseTrace(trName, st); err != nil {
			t.Log(err)
			t.Fail()
		} else {
			if newRule, err := tr.Compile(trigger, "foo"); err != nil {
				t.Fail()
			} else {
				t.Log(newRule)
			}
		}
	}
}

func TestRuleWithTrace(t *testing.T) {
	ef, err := evtx.New(testFile)
	if err != nil {
		t.Log(err)
		t.Fail()
	}
	e := engine.NewEngine(true)
	if trigger, err := rules.Load([]byte(triggerRule), nil); err != nil {
		t.Log(err)
		t.Fail()
	} else {
		e.AddRule(trigger)
		t.Log(trigger)
	}
	log.Debugf("Rules Loaded: %d", e.Count())
	for event := range ef.FastEvents() {
		if m, _ := e.Match(event); len(m) > 0 {
			t.Log(string(evtx.ToJSON(event)))
		}
	}
}
