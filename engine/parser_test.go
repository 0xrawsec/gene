package engine

import (
	"runtime"
	"testing"

	"github.com/0xrawsec/toast"
)

var (
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
	tt := toast.FromT(t)

	fms := []*FieldMatch{
		{Name: "$foo", Operand: "Hashes", Operator: "~=", Value: "83514D9AAF0E168944B6D3C01110C393", format: &TypeWinevt},
		{Name: "$foo", Operand: "CommandLine", Operator: "=", Value: "C:\\Windows\\system32\\devicecensus.exe", format: &TypeWinevt},
		{Name: "$foo", Operand: "LogonId", Operator: "&=", Value: "1", format: &TypeWinevt},
		{Name: "$foo", Operand: "LogonId", Operator: ">", Value: "1", format: &TypeWinevt},
		{Name: "$foo", Operand: "LogonId", Operator: ">=", Value: "0x000003e7", format: &TypeWinevt},
		{Name: "$foo", Operand: "LogonId", Operator: "<=", Value: "0x000003e7", format: &TypeWinevt},
	}

	for _, fm := range fms {
		tt.Assert(fm.Match(winevtEvent))
	}

}

func TestParseAtomRule(t *testing.T) {

	tt := toast.FromT(t)

	parse := func(mn, m string) (err error) {
		_, err = parseFieldMatch(mn, m, &TypeWinevt)
		return
	}

	tt.CheckErr(parse("$hello", `"Hashes = Test" = 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse("$test", `"Hashes" = 'c'est un super test'`))
	tt.CheckErr(parse("$h", `Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse("$h", `/Event/EventData/Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))
	tt.CheckErr(parse("$h", `Event/EventData/Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))

	// Syntax is not correct, space is not allowed in field without quotes
	tt.ExpectErr(parse("$h", `Event/EventData/Some Field ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`), ErrSyntax)

	// Spaces are accepted when field is quoted
	tt.CheckErr(parse("$h", `"Event/EventData/Some Field" ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'`))

	// testing indirect matches
	tt.CheckErr(parse("$indmatch", `SourceProcessGuid = @TargetProcessGuid`))
	tt.CheckErr(parse("$indmatch", `/Event/EventData/SourceProcessGuid = @TargetProcessGuid`))
	tt.CheckErr(parse("$indmatch", `/Event/EventData/SourceProcessGuid = @/Event/EventData/TargetProcessGuid`))
}

func TestParseCondition(t *testing.T) {
	for _, cond := range conditions {
		t.Log(cond)
		tokenizer := NewTokenizer(cond)
		_, err := tokenizer.ParseCondition(0, 0)
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
		t.Logf("Pretty Co: %s", Pretty(cond, false))
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

func TestRule(t *testing.T) {
	tt := toast.FromT(t)

	er := NewCompiledRule()
	er.EventFilter = NewEventFilter(map[string][]int64{"Microsoft-Windows-Sysmon/Operational": {1, 7}})

	as := `Hashes ~= '83514D9AAF0E168944B6D3C01110C393'`
	a, err := parseFieldMatch("$a", as, &TypeWinevt)
	tt.CheckErr(err)
	er.AddMatcher(&a)

	bs := `Hashes ~= '83514D9AAF0E168944B6D3C011424242'`
	b, err := parseFieldMatch("$b", bs, &TypeWinevt)
	tt.CheckErr(err)
	er.AddMatcher(&b)

	ym := `IntegrityLevel = 'System'`
	y, err := parseFieldMatch("$y", ym, &TypeWinevt)
	tt.CheckErr(err)
	er.AddMatcher(&y)

	condStr := "$b or ($a and $y)"
	tokenizer := NewTokenizer(condStr)
	cond, err := tokenizer.ParseCondition(0, 0)
	tt.CheckErr(err)
	er.Conditions = cond
	tt.Log(cond.DebugString())

	tt.Assert(er.Match(winevtEvent))
}

func TestLoadRule(t *testing.T) {
	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "Test",
	"Tags": ["Hello", "World"],
	"Meta": {
		"LogType": "winevt",
		"Events": {
			"Microsoft-Windows-Sysmon/Operational": [1,7]
		},
		"Computers": ["DESKTOP-5SUA567"]
		},
	"Matches": {
		"$a": "Hashes ~= '83514D9AAF0E168944B6D3C01110C393'",
		"$b": "Hashes ~= 'Not'",
		"$c": "Image ~= '(?i:DeviceCENSUS\\.exe$)'"
		},
	"Condition": "$c and $a and (!$b)"
	}`

	er, err := LoadRule([]byte(ruleStr), nil)
	tt.CheckErr(err)

	tt.Assert(er.Match(winevtEvent))

}

func TestParseContainerMatch(t *testing.T) {

	tt := toast.FromT(t)

	parse := func(mn, m string) (err error) {
		_, err = parseContainerMatch(mn, m, &TypeWinevt)
		return
	}

	tt.CheckErr(parse("$inBlacklist", "extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist"))
	tt.CheckErr(parse("$inBlacklist", "extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Hashes) in blacklist"))

	// testing syntax error
	tt.ExpectErr(parse("$inBlacklist", "extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Some Hashes) in blacklist"), ErrSyntax)
	// quoted path should not raise syntax error
	tt.CheckErr(parse("$inBlacklist", `extract('SHA1=(?P<sha1>[A-F0-9]{40})', "/Event/EventData/Some Hashes") in blacklist`))

	r, err := parseContainerMatch("$inBlacklist", "extract('SHA1=(?P<sha1>[A-F0-9]{40})', /Event/EventData/Hashes) in blacklist", &TypeWinevt)
	tt.CheckErr(err)
	tt.Assert(r.path.Flags.EventDataField)
}

func TestBlacklist(t *testing.T) {
	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "Blacklisted",
	"Tags": ["Hello", "World"],
	"Meta": {
		"Events": {
			"Microsoft-Windows-Sysmon/Operational": [1,7]
		}
	},
	"Matches": {
		"$sha1In": "extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist",
		"$md5InBl": "extract('(?P<md5>83514D9AAF0E168944B6D3C01110C393)', Hashes) in blacklist",
		"$md5InWl": "extract('(?P<md5>83514D9AAF0E168944B6D3C01110C393)', Hashes) in whitelist"
		},
	"Condition": "$md5InBl and $sha1In and !$md5InWl"
	}`

	containers := NewContainers()
	// adding md5
	containers.AddStringToContainer("blacklist", "83514D9AAF0E168944B6D3C01110C393")
	// adding sha1
	containers.AddStringToContainer("blacklist", "65894B0162897F2A6BB8D2EB13684BF2B451FDEE")
	// bogus value in whitelist, we don't care what's in it
	containers.AddStringToContainer("whitelist", "turbo fish")

	er, err := LoadRule([]byte(ruleStr), containers)

	tt.CheckErr(err)
	tt.Assert(er.Match(winevtEvent))

}

func TestIndirectMatch(t *testing.T) {

	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "IndirectMatch",
	"Meta": {
		"Events": {
			"Microsoft-Windows-Sysmon/Operational": [1,7]
		}
	},
	"Matches": {
		"$dummyIndirect": "Hashes = @Hashes",
		"$abs": "/Event/System/Computer = @/Event/System/Computer",
		"$fail": "/Event/System/Computer = @/Event/System/Channel"
		},
	"Condition": "$dummyIndirect and $abs and !$fail"
	}`

	er, err := LoadRule([]byte(ruleStr), nil)

	tt.CheckErr(err)

	tt.Assert(er.Match(winevtEvent))

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

	er, err := LoadRule([]byte(ruleStr), nil)
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

	er, err := LoadRule([]byte(ruleStr), nil)
	tt.CheckErr(err)
	tt.Assert(er.OSs.Len() == 3)

	tt.Assert(er.matchOS("windows"))
	tt.Assert(er.matchOS("linux"))
	tt.Assert(er.matchOS("darwin"))
	tt.Assert(er.matchOS(runtime.GOOS))

	tt.Assert(!er.matchOS("ios"))
	tt.Assert(!er.matchOS("android"))

	// testing that we return ErrInvalidOS on invalid OS
	_, err = LoadRule([]byte(`
	{
	"Name": "TestOSMatch",
	"Meta": {
		"OSs": ["invalid_os"]
		}
	}`), nil)

	tt.ExpectErr(err, ErrInvalidOS)
}

func TestAuthorsComments(t *testing.T) {

	tt := toast.FromT(t)

	ruleStr := `{
	"Name": "TestAuthorsComments",
	"Meta": {
		"Authors": [
			"0xrawsec",
			"Santa"
		],
		"Comments": [
			"Some useful comment",
			"Another comment"
			]
		}
	}`

	_, err := LoadRule([]byte(ruleStr), nil)
	tt.CheckErr(err)
}
