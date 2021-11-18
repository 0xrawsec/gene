package engine

import (
	"testing"
)

var (
	corruptedRules = map[string]string{
		"JSON Error": `{
			"Name":"Rule1",
			"Matches": [,
				"$a: Test = 'foo'"
			],
			"Condition": "$a"
		}`,
		"Unknown Operand": `{
			"Name":"Rule1",
			"Matches": [
				"$a: Test = 'foo'"
			],
			"Condition": "$a and $unknown"
		}`,
		"Syntax Error": `{
			"Name":"Rule1",
			"Matches": [
				"$a: Test = foo"
			],
			"Condition": "$a and $unknown"
		}`,
		"Trace Error": `{
			"Name":"Rule1",
			"Meta": {
				"Traces": [
				"foo:: ProcessGuid = ProcessGuid"
				]
			},
			"Matches": [
				"$a: Test = 'foo'"
			],
			"Condition": "$a"
		}`,
		"Condition Error": `{
			"Name":"Rule1",
			"Matches": [
				"$a: Test = 'foo'"
			],
			"Condition": "$a and foobar"
		}`,
	}
)

func TestValidation(t *testing.T) {
	e := NewEngine()
	for k, v := range corruptedRules {
		err := e.LoadReader(NewSeekBuffer([]byte(v)))
		if err != nil {
			t.Logf("%s failed with: %s", k, err)
			continue
		}
		t.Logf("%s parsing should have failed", v)
		t.FailNow()
	}
}
