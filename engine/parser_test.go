package engine

import (
	"runtime"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/toast"
)

var (
	testFile = "./test/data/sysmon.evtx"

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

func TestAtomRule(t *testing.T) {
	f, err := evtx.OpenDirty(testFile)
	if err != nil {
		t.Error(err)
		return
	}

	fm := &FieldMatch{Name: "$foo", Operand: "Hashes", Operator: "=", Value: "B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA", format: &TypeWinevt}

	for e := range f.FastEvents() {
		ge := GenericEvent(*e)
		if fm.Match(ge) {
			t.Log(string(evtx.ToJSON(e)))
		}
	}
}

func TestParseAtomRule(t *testing.T) {

	tt := toast.FromT(t)

	parse := func(m string) (err error) {
		_, err = ParseFieldMatch(m, &TypeWinevt)
		return
	}

	tt.CheckErr(parse(`$hello: "Hashes = Test" = 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse(`$test: "Hashes" = 'c'est un super test'`))
	tt.CheckErr(parse(`$h: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse(`$h: /Event/EventData/Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse(`$h: Event/EventData/Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))

	// Syntax is not correct, space is not allowed in field without quotes
	tt.ExpectErr(parse(`$h: Event/EventData/Some Field ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`), ErrSyntax)

	// Spaces are accepted when field is quoted
	tt.CheckErr(parse(`$h: "Event/EventData/Some Field" ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))

	// testing indirect matches
	tt.CheckErr(parse(`$indmatch: SourceProcessGuid = @TargetProcessGuid`))
	tt.CheckErr(parse(`$indmatch: /Event/EventData/SourceProcessGuid = @TargetProcessGuid`))
	tt.CheckErr(parse(`$indmatch: /Event/EventData/SourceProcessGuid = @/Event/EventData/TargetProcessGuid`))
}

func TestParseCondition(t *testing.T) {
	for _, cond := range conditions {
		t.Log(cond)
		tokenizer := NewTokenizer(cond)
		cond, err := tokenizer.ParseCondition(0, 0)
		if err != nil {
			t.FailNow()
			t.Logf("%s Error:%v", cond, err)
		}
	}
}

func TestCondition(t *testing.T) {
	for strCond, expectRes := range conditionMap {
		tokenizer := NewTokenizer(strCond)
		cond, err := tokenizer.ParseCondition(0, 0)
		if err != nil {
			t.Logf("%s Error:%v", cond, err)
			t.FailNow()
		}
		t.Logf("Condition: %s", strCond)
		t.Logf("Pretty Co: %s", cond.Pretty(false))
		t.Logf("Parsed Condition: %s", cond)
		cond.Prioritize()
		//t.Logf("Priori Condition: %s", cond)
		t.Logf("Pretty Pr: %s", cond.Pretty(false))
		result := Compute(cond, operands)
		t.Logf("Cond: %s With: %v => Result: %t", cond, operands, result)
		if result != expectRes {
			t.Log("Unexpected result")
			t.FailNow()
		}
	}
}

func TestBuggyCondition(t *testing.T) {
	//buggy := "(!$b and !(!($b or !$a) or $a))"
	buggy := "!(!($a and $b and $a and !$a and !$b or !$b) and !$a)"
	expectRes := true
	tokenizer := NewTokenizer(buggy)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil {
		t.Logf("%s Error:%v", cond, err)
		t.FailNow()
	}
	t.Logf("Condition: %s", buggy)
	t.Logf("Pretty Co: %s", cond.Pretty(false))
	t.Logf("Parsed Condition: %s", cond)
	cond.Prioritize()
	//t.Logf("Priori Condition: %s", cond)
	t.Logf("Pretty Pr: %s", cond.Pretty(false))
	result := Compute(cond, operands)
	t.Logf("Cond: %s With: %v => Result: %t", cond, operands, result)
	if result != expectRes {
		t.Log("Unexpected result")
		t.FailNow()
	}
}

func TestEvtxRule(t *testing.T) {
	er := NewCompiledRule(Version{})
	er.EventFilter = NewEventFilter(map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {1, 7}})

	f, err := evtx.OpenDirty(testFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	as := `$a: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`
	a, err := ParseFieldMatch(as, &TypeWinevt)
	if err != nil {
		t.Logf("Failed to parse: %s", as)
		t.Fail()
	}

	bs := `$b: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FB'`
	b, err := ParseFieldMatch(bs, &TypeWinevt)
	if err != nil {
		t.Logf("Failed to parse: %s", bs)
		t.Fail()
	}

	er.AddMatcher(&a)
	er.AddMatcher(&b)

	condStr := "$b or ($a and $y)"
	tokenizer := NewTokenizer(condStr)
	cond, err := tokenizer.ParseCondition(0, 0)
	if err != nil {
		t.Logf("Failed to parse: %s", condStr)
		t.Fail()
	}
	er.Conditions = cond

	count := 0
	for e := range f.FastEvents() {
		ge := GenericEvent(*e)
		if er.Match(ge) {
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}
	t.Logf("Scanned events: %d", count)
}

func TestLoadRule(t *testing.T) {
	f, err := evtx.OpenDirty(testFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ruleStr := `{
	"Name": "Test",
	"Tags": ["Hello", "World"],
	"Meta": {
		"LogType": "winevt",
		"EventIDs": [1,7],
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
	er, err := Load([]byte(ruleStr), nil, &TypeWinevt)
	if err != nil {
		t.Logf("Error parsing string rule: %s", err)
		t.FailNow()
	}

	count := 0
	for e := range f.FastEvents() {
		ge := GenericEvent(*e)
		if er.Match(ge) {
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}
	t.Logf("Scanned events: %d", count)
}

func TestParseContainerMatch(t *testing.T) {

	tt := toast.FromT(t)

	parse := func(m string) (err error) {
		_, err = ParseContainerMatch(m, &TypeWinevt)
		return
	}

	tt.CheckErr(parse("$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist"))
	tt.CheckErr(parse("$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Hashes) in blacklist"))

	// testing syntax error
	tt.ExpectErr(parse("$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Some Hashes) in blacklist"), ErrSyntax)
	// quoted path should not raise syntax error
	tt.CheckErr(parse(`$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', "/Event/EventData/Some Hashes") in blacklist`))

	r, err := ParseContainerMatch("$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Hashes) in blacklist", &TypeWinevt)
	tt.CheckErr(err)
	tt.Assert(r.path.Flags.EventDataField)
}

func TestBlacklist(t *testing.T) {
	f, err := evtx.OpenDirty(testFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ruleStr := `{
	"Name": "Blacklisted",
	"Tags": ["Hello", "World"],
	"Meta": {
		"EventIDs": [1,7],
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"Computer": ["Test"],
		"Action": "warn"
		},
	"Matches": [
		"$inBlacklist: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist",
		"$inBullshit: extract('(?P<md5>B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA)', Hashes) in bullshit"
		],
	"Condition": "$inBlacklist"
	}`
	containers := NewContainers()
	containers.AddToContainer(black, "B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA")
	er, err := Load([]byte(ruleStr), containers, &TypeWinevt)
	if err != nil {
		t.Logf("Error parsing string rule: %s", err)
		t.FailNow()
	}

	count := 0
	for e := range f.FastEvents() {
		ge := GenericEvent(*e)
		if er.Match(ge) {
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}
	t.Logf("Scanned events: %d", count)
}

func TestIndirectMatch(t *testing.T) {
	eventCnt, matchCnt := 0, 0

	f, err := evtx.OpenDirty(testFile)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ruleStr := `{
	"Name": "IndirectMatch",
	"Meta": {
		"EventIDs": [1, 6, 7],
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"Computer": ["Test"],
		"Action": "warn"
		},
	"Matches": [
		"$dummyIndirect: Hashes = @Hashes"
		],
	"Condition": "$dummyIndirect"
	}`
	er, err := Load([]byte(ruleStr), nil, &TypeWinevt)
	if err != nil {
		t.Logf("Error parsing string rule: %s", err)
		t.FailNow()
	}

	count := 0
	for e := range f.FastEvents() {
		ge := GenericEvent(*e)
		switch ge.EventID() {
		case 1, 6, 7:
			eventCnt++
		}
		if er.Match(ge) {
			matchCnt++
			t.Log(string(evtx.ToJSON(e)))
		}
		count++
	}

	if eventCnt != matchCnt {
		t.Errorf("Unexpected number of matched events expected %d VS %d matched", eventCnt, matchCnt)
	}

	t.Logf("Scanned events: %d", count)
}

func TestMatchEvent(t *testing.T) {

	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "TestMatchEvent",
	"Meta": {
		"Events": {
			"kunai": [1],
			"Microsoft-Windows-Sysmon/Operational": [1]
			}
		}
	}`

	er, err := Load([]byte(ruleStr), nil, &TypeWinevt)
	tt.CheckErr(err)
	tt.Assert(!er.EventFilter.IsEmpty(), "filter should not be empty")

	tt.Assert(er.EventFilter.match("kunai", 1))
	tt.Assert(!er.EventFilter.match("kunai", 42))

	tt.Assert(er.EventFilter.match("Microsoft-Windows-Sysmon/Operational", 1))
	tt.Assert(!er.EventFilter.match("Microsoft-Windows-Sysmon/Operational", 42))
}

func TestMatchOS(t *testing.T) {

	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "TestOSMatch",
	"Meta": {
		"OSs": ["windows", "Linux", "DARWIN"]
		}
	}`

	er, err := Load([]byte(ruleStr), nil, nil)
	tt.CheckErr(err)
	tt.Assert(er.OSs.Len() == 3)

	tt.Assert(er.matchOS("windows"))
	tt.Assert(er.matchOS("linux"))
	tt.Assert(er.matchOS("darwin"))
	tt.Assert(er.matchOS(runtime.GOOS))

	tt.Assert(!er.matchOS("ios"))
	tt.Assert(!er.matchOS("android"))

	// testing that we return ErrInvalidOS on invalid OS
	er, err = Load([]byte(`
	{
	"Name": "TestOSMatch",
	"Meta": {
		"OSs": ["invalid_os"]
		}
	}`), nil, nil)
	tt.ExpectErr(err, ErrInvalidOS)
}
