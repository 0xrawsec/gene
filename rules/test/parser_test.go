package main

import (
	"rules"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/log"
)

var (
	testFile    = "sysmon.evtx"
	ar          = rules.NewAtomRule("$foo", "Hashes", "=", "B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA")
	rulesString = [...]string{
		`$hello: "Hashes = Test" = 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`,
		`$test: "Hashes" = "c'est un super test"`,
		`$h: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`}
	conditions = []string{
		`$a or $b`,
		`$a and ( $b or $c )`,
		`( $a or $b) and ($c or $d ) and $e`,
		`( $a or $b) and ($c or $d ) and !$e`,
		`( $a or $b) and ( $c or $d ) and !$e`,
		`( $a or $b) and ($c or ($d and !$e) ) and !$f`,
		`!( $a or $b) and ($c or ($d and !$e) ) and !$f`,
	}
)

func init() {
	//log.InitLogger(log.LDebug)
}

func TestAtomRule(t *testing.T) {
	f, err := evtx.New(testFile)
	if err != nil {
		log.LogError(err)
		return
	}

	for e := range f.FastEvents() {
		if ar.Match(e) {
			t.Log(string(evtx.ToJSON(e)))
		}
	}
}

func TestParseAtomRule(t *testing.T) {
	for _, rule := range rulesString {
		ar, err := rules.ParseAtomRule(rule)
		if err != nil {
			t.Log(err)
			t.Fail()
		}
		t.Log(ar)
	}
}

func TestParseCondition(t *testing.T) {
	for _, cond := range conditions {
		t.Log(cond)
		tokenizer := rules.NewTokenizer(cond)
		cond, err := tokenizer.ParseCondition(0, 0)
		if err != nil {
			t.FailNow()
			t.Logf("%s Error:%v", &cond, err)
		}
	}
}

var (
	operands = map[string]bool{"$a": true, "$b": false}
	// Key: condition Value: expected result according to operands
	conditionMap = map[string]bool{
		"$a":                                             true,
		"$b":                                             false,
		"!$a":                                            false,
		"!$b":                                            true,
		"$a or $b":                                       true,
		"$a and $b":                                      false,
		"($a and !$b)":                                   true,
		"((($a and !$b)))":                               true,
		"$a and ($b or !$b)":                             true,
		"!($a or $b) or $a":                              true,
		"$a and !$b and !$a":                             false,
		"!($a and $b or !($a and $b))":                   false,
		"!($a or $b) and ($a or ($b and !$a)) and !$a":   false,
		"!$b or (!($a or $b) and ($a or ($b and !$a)))":  true,
		"(!($a or $b) and ($a or ($b and !$a)))":         false,
		"(($a and !$b) and $a)":                          true,
		"(!($a and $b) and $b)":                          false,
		"(!($a and $b) and $b) or (($a and !$b) and $a)": true,
	}
)

func TestCondition(t *testing.T) {
	for strCond, expectRes := range conditionMap {
		tokenizer := rules.NewTokenizer(strCond)
		cond, err := tokenizer.ParseCondition(0, 0)
		if err != nil {
			t.Logf("%s Error:%v", &cond, err)
			t.FailNow()
		}
		t.Logf("Parsed Condition: %s", &cond)
		result := rules.Compute(&cond, operands)
		t.Logf("Cond: %s With: %v => Result: %t", &cond, operands, result)
		if result != expectRes {
			t.Log("Unexpected result")
			t.FailNow()
		}
	}
}

func TestEvtxRule(t *testing.T) {
	er := rules.NewCompiledRule()
	er.EventIDs.Add(int(1), int(7))

	f, err := evtx.New(testFile)
	if err != nil {
		log.LogError(err)
		t.FailNow()
	}

	as := `$a: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`
	a, err := rules.ParseAtomRule(as)
	if err != nil {
		t.Logf("Failed to parse: %s", as)
		t.Fail()
	}

	bs := `$b: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FB'`
	b, err := rules.ParseAtomRule(bs)
	if err != nil {
		t.Logf("Failed to parse: %s", bs)
		t.Fail()
	}

	er.AddAtom(&a)
	er.AddAtom(&b)

	condStr := "$b or ($a and $y)"
	tokenizer := rules.NewTokenizer(condStr)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil {
		t.Logf("Failed to parse: %s", condStr)
		t.Fail()
	}
	er.Conditions = &cond

	count := 0
	for e := range f.FastEvents() {
		if er.Match(e) {
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}
	t.Logf("Scanned events: %d", count)
}

func TestLoadRule(t *testing.T) {
	f, err := evtx.New(testFile)
	if err != nil {
		log.LogError(err)
		t.FailNow()
	}

	ruleStr := `{
	"Name": "Test",
	"Tags": ["Hello", "World"],
	"Meta": {
		"EventID": [1,7],
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"Computer": ["Test"],
		"Action": "warn"
		},
	"Matches": [
		"$a: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'",
		"$b: Hashes ~= '7D2AB43576DEA34829209710CC711DB172DCC07E'",
		"$c: ImageLoaded ~= '(?i:wininet\\.dll$)'"
		],
	"Condition": "$c"
	}`
	er, err := rules.Load([]byte(ruleStr))
	if err != nil {
		t.Logf("Error parsing string rule: %s", err)
		t.FailNow()
	}

	count := 0
	for e := range f.FastEvents() {
		if er.Match(e) {
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}
	t.Logf("Scanned events: %d", count)

}
