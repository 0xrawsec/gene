package engine

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/toast"
)

const (
	eventStr = `
	{
  "Event": {
    "EventData": {
      "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
      "CurrentDirectory": "C:\\Windows\\system32\\",
      "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
      "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
      "IntegrityLevel": "System",
      "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
      "LogonId": "0x000003e7",
      "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
      "ParentImage": "C:\\Windows\\System32\\svchost.exe",
      "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
      "ParentProcessId": "828",
      "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
      "ProcessId": "3516",
      "TerminalSessionId": "0",
      "User": "NT AUTHORITY\\SYSTEM",
      "UtcTime": "2017-01-19 16:09:30.252"
    },
    "System": {
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "DESKTOP-5SUA567",
      "Correlation": {},
      "EventID": "1",
      "EventRecordID": "123661",
      "Execution": {
        "ProcessID": "1760",
        "ThreadID": "1952"
      },
      "Keywords": "0x8000000000000000",
      "Level": "4",
      "Opcode": "0",
      "Provider": {
        "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
        "Name": "Microsoft-Windows-Sysmon"
      },
      "Security": {
        "UserID": "S-1-5-18"
      },
      "Task": "1",
      "TimeCreated": {
        "SystemTime": "2017-01-19T16:09:30Z"
      },
      "Version": "5"
    }
  }
}`
)

var (
	winevtEvent = make(GenericEvent)
	bigRuleFile = "./test/data/1000rules.json"
)

func init() {
	err := json.Unmarshal([]byte(eventStr), &winevtEvent)
	if err != nil {
		panic(err)
	}
}

func eventFromString(s string) (evt *GenericEvent) {
	evt = &GenericEvent{}
	err := json.Unmarshal([]byte(s), evt)
	if err != nil {
		panic(err)
	}
	return
}

func prettyJSON(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestLoad(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Schema": "2.0.0"
	},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
}

func TestMatch(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestShouldNotMatch(t *testing.T) {
	rule := `{
	"Name": "ShouldNotMatch",
	"Meta": {
		"Events": {"Microsoft-Windows-Sysmon/Operational": [666]},
		"Schema": "2.0.0"
		},
	"Matches": [],
	"Condition": ""
	}`

	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) != 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestMatchAttck(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"ATTACK": [
			{
				"ID": "T666",
				"Tactic": "Blow everything up",
				"Reference": "https://attack.mitre.org/"
			},
			{
				"ID": "S4242",
				"Description": "Super nasty software",
				"Reference": "https://attack.mitre.org/"
			}
		],
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine()
	e.SetShowAttck(true)
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(prettyJSON(winevtEvent))
	}
}

func TestMatchByTag(t *testing.T) {
	rules := `{
	"Name": "ShouldMatch",
	"Tags": ["foo"],
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}

	{
	"Name": "ShouldNotMatch",
	"Tags": ["bar"],
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}
	`

	e := NewEngine()
	tags := []string{"foo"}
	e.SetFilters([]string{}, tags)

	if err := e.LoadString(rules); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())

	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}

}

func TestSimpleRule(t *testing.T) {
	rule := `{
	"Name": "SimpleRule",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Engine loaded %d rule", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestNotOrRule(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "NotOrRule",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'"
		],
	"Condition": "!($a or $b)"
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	// The match should fail
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) != 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestNotAndRule(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "NotAndRule",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'"
		],
	"Condition": "!($a and !$b)"
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	// The match should fail
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestComplexRule(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "ComplexRule",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'",
		"$c: CommandLine = 'C:\\Windows\\system32\\devicecensus.exe'",
		"$d: Image = 'C:\\Windows\\System32\\DeviceCensus.exe'",
		"$e: IntegrityLevel = 'Blop'",
		"$f: LogonGuid = 'B2796A13-618F-5881-0000-0020E7030000'"
		],
	"Condition": "!($a and !$b) and ($c or ($d and !$e) ) and $f"
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestContainer(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "ContainerConditions",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$md5: extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in blacklist",
		"$sha1: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist",
		"$sha256: extract('SHA256=(?P<sha1>[A-F0-9]{64})', Hashes) in blacklist"
		],
	"Condition": "$md5 and $sha1 and $sha256"
	}
	`
	e := NewEngine()
	// Container update has to be done before loading rules
	e.AddToContainer("blacklist", "83514d9aaf0e168944b6d3c01110c393")
	e.AddToContainer("blacklist", "65894b0162897f2a6bb8d2eb13684bf2b451fdee")
	e.AddToContainer("blacklist", "03324e67244312360ff089cf61175def2031be513457bb527ae0abf925e72319")
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestFiltered1(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "ProcessCreate",
	"Meta": {
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Filter": true,
		"Schema": "2.0.0"
		},
	"Matches": [],
	"Condition": ""
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if _, _, filtered := e.MatchOrFilter(&winevtEvent); filtered {
		t.Log("Event correctly filtered")
		t.Logf("%s", prettyJSON(winevtEvent))
	} else {
		t.Fail()
	}
}

func TestFiltered2(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "ProcessCreate",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": [1]},
		"Filter": true,
		"Schema": "2.0.0"
		},
	"Matches": [],
	"Condition": ""
	}
	
	{
	"Name": "SimpleRule",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if m, _, filtered := e.MatchOrFilter(&winevtEvent); filtered && len(m) > 0 {
		t.Log("Event is both an alert and filtered")
	} else {
		t.Logf("Matches: %s", m)
		t.Logf("Filtered: %t", filtered)
		t.Log(prettyJSON(winevtEvent))
		t.Fail()
	}
}

func TestNotFiltered(t *testing.T) {
	/*
	   "CommandLine": "C:\\Windows\\system32\\devicecensus.exe",
	   "CurrentDirectory": "C:\\Windows\\system32\\",
	   "Hashes": "SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,MD5=83514D9AAF0E168944B6D3C01110C393,SHA256=03324E67244312360FF089CF61175DEF2031BE513457BB527AE0ABF925E72319,IMPHASH=D9EA1DE97F43E8F8608832D8E83DA2CF",
	   "Image": "C:\\Windows\\System32\\DeviceCensus.exe",
	   "IntegrityLevel": "System",
	   "LogonGuid": "B2796A13-618F-5881-0000-0020E7030000",
	   "LogonId": "0x000003e7",
	   "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
	   "ParentImage": "C:\\Windows\\System32\\svchost.exe",
	   "ParentProcessGuid": "B2796A13-6191-5881-0000-00100FD80000",
	   "ParentProcessId": "828",
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC01100",
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/
	rule := `{
	"Name": "ProcessCreate",
	"Meta": {
		"Events": {"Microsoft-Windows-Sysmon/Operational": [2]},
		"Filter": true,
		"Schema": "2.0.0"
		},
	"Matches": [],
	"Condition": ""
	}
	`
	e := NewEngine()
	if err := e.LoadString(rule); err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if _, _, filtered := e.MatchOrFilter(&winevtEvent); !filtered {
		t.Log("Event not filtered")
	} else {
		t.Fail()
	}
}

func TestLoadDirectory(t *testing.T) {
	tt := toast.FromT(t)
	e := NewEngine()

	dir := t.TempDir()
	count := 42

	for i := 0; i < count; i++ {
		rule := fmt.Sprintf(`{
	"Name": "ShouldMatch_%d",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a",
	"Actions": ["kill", "kill", "block", "block"]
	}`, i)

		tt.CheckErr(os.WriteFile(filepath.Join(dir, fmt.Sprintf("rule_%d.gen", i)), []byte(rule), 0777))
	}

	tt.CheckErr(e.LoadDirectory(dir))
	tt.Assert(e.Count() == count)
}

func TestActions(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a",
	"Actions": ["kill", "kill", "block", "block"]
	}`

	e := NewEngine()
	e.ShowActions = true
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(string(prettyJSON(winevtEvent)))
	}
}

func TestDefaultActions(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine()
	e.ShowActions = true
	actions := []string{"kill", "kill", "block", "block"}
	e.SetDefaultActions(0, 10, actions)
	if err := e.LoadString(rule); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _, _ := e.MatchOrFilter(&winevtEvent); len(m) == 0 {
		t.Fail()
	} else {
		if i, ok := winevtEvent.Get(GeneInfoPath); ok {
			if det, ok := i.(*Detection); ok {
				for _, act := range actions {
					if !det.Actions.Contains(act) {
						t.Errorf("default action not set as intended")
					}
				}
			}

		}
		t.Log(string(prettyJSON(winevtEvent)))
	}
}

func TestLoadContainer(t *testing.T) {
	var cfd *os.File
	var err error

	size := 10000
	cname := "container"
	tmp := t.TempDir()
	container := filepath.Join(tmp, "container.cont")

	if cfd, err = os.Create(container); err != nil {
		t.Error(err)
		t.FailNow()
	}

	for i := 0; i < size; i++ {
		cfd.WriteString(fmt.Sprintf("random.%d\n", rand.Int()))
	}

	if err = cfd.Close(); err != nil {
		t.Error(err)
		t.FailNow()
	}

	e := NewEngine()
	if cfd, err = os.Open(container); err != nil {
		t.Error(err)
		t.FailNow()
	}

	if err = e.LoadContainer(cname, cfd); err != nil {
		t.Error(err)
	}

	if e.containers.Len(cname) != size {
		t.Error("Unexpected container length")
	}
}

func TestGetRule(t *testing.T) {
	collect := func(c chan string) (out []string) {
		for s := range c {
			out = append(out, s)
		}
		return
	}

	tt := toast.FromT(t)

	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"LogType": "winevt",
		"Events": {"Microsoft-Windows-Sysmon/Operational": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine()
	e.SetDumpRaw(true)

	tt.CheckErr(e.LoadString(rule))

	tt.Assert(len(collect(e.GetRawRule("Should"))) == 1)

	tt.Assert(e.GetRawRuleByName("ShouldMatch") != "")
	tt.Assert(e.GetCRuleByName("ShouldMatch") != nil)

	tt.Assert(e.GetRawRuleByName("XYZ") == "")
	tt.Assert(e.GetCRuleByName("XYZ") == nil)

	names := e.GetRuleNames()
	tt.Assert(len(names) == 1)
	tt.Assert(names[0] == "ShouldMatch")
}

func TestLoadingOldFormat(t *testing.T) {

	tt := toast.FromT(t)

	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"EventIDs" : [1, 7],
		"Channels" : ["Microsoft-Windows-Sysmon/Operational"],
		"Schema": "2.0.0"
		},
	"Condition": ""
	}`

	e := NewEngine()

	tt.Assert(e.LoadString(rule) != nil)
}

func TestAbsolutePath(t *testing.T) {

	tt := toast.FromT(t)

	event := `
	{
	"data": {
		"ancestors": "/usr/lib/systemd/systemd|/usr/bin/bash|/usr/bin/urxvt|/usr/bin/zsh",
		"parent_exe": "/usr/bin/zsh",
		"command_line": "ping google.com",
		"exe": {
			"file": "/usr/bin/ping",
			"md5": "2d57c5245652e40bbf51edaaa3be65bd",
			"sha1": "b35e159eb1ddcfe72a8b0f38cab8c2d889b8b642",
			"sha256": "17cb2147feadef7158150be9bbc6deb7877054072813f1c29ce172c809e71f86",
			"sha512": "da08973ee6c40626050e65c1cd4498e1df59a0a0717921f62922f670440dde77b1757bee5c701fae728d7080d9ede440af839a0679f534b2f1d4f0ec03a73f72",
			"size": 93648
		}
	},
	"info": {
		"event": {
			"source": "kunai",
			"id": 1,
			"name": "execve",
			"uuid": "d959b042-e321-be26-1437-6536b2006da0",
			"batch": 0
			}
		}
	}
	`

	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"Events" : {"kunai": []},
		"Schema": "2.0.0"
		},
	"Matches": [
		"$a: exe/file = '/usr/bin/ping'",
		"$b: /data/exe/md5 = '2d57c5245652e40bbf51edaaa3be65bd'"
	],
	"Condition": "$a and $b"
	}`

	e := NewEngine()

	tt.CheckErr(e.LoadString(rule))
	names, _, _ := e.MatchOrFilter(eventFromString(event))
	tt.Logf("names: %s", names)
	tt.Assert(len(names) > 0)
}

/////////////////////////////// Benchmarks /////////////////////////////////////

func BenchmarkLoadThousand(b *testing.B) {
	e := NewEngine()
	if err := e.LoadFile(bigRuleFile); err != nil {
		b.Logf("Loading failed: %s", err)
		b.FailNow()
	}
	b.Logf("Engine loaded %d rules", e.Count())
}

func BenchmarkEngine(b *testing.B) {
	var err error
	var fd *os.File
	var r *gzip.Reader
	var bytesScanned uint64

	loops := 5
	events := make([]GenericEvent, 0)

	eventsFile := "./test/data/events.json.gz"
	rulePath := "./test/data/compiled.gen"
	e := NewEngine()

	// loading rules into engine
	if err := e.LoadFile(rulePath); err != nil {
		b.Errorf("Loading failed: %s", err)
		b.FailNow()
	}

	if fd, err = os.Open(eventsFile); err != nil {
		b.Errorf("Fail at opening event file: %s", err)
		b.FailNow()
	}
	defer fd.Close()

	// loading all events in memory
	if r, err = gzip.NewReader(fd); err != nil {
		b.Errorf("Failed at creating gzip reader: %s", err)
		b.FailNow()
	}

	for line := range readers.Readlines(r) {
		e := GenericEvent{}
		if err = json.Unmarshal(line, &e); err != nil {
			b.Errorf("Failed at unmarshaling event: %s", err)
			b.FailNow()
		}
		events = append(events, e)
		bytesScanned += uint64(len(line))
	}
	r.Close()

	start := time.Now()
	for i := 0; i < loops; i++ {
		for _, evt := range events {
			e.MatchOrFilter(evt)
		}
	}
	stop := time.Now()

	// statistics

	// we have to multiply the number of bytes scanned by the
	// number of loops we have done
	bytesScanned *= uint64(loops)
	dmatch := stop.Sub(start)
	eps := float64(e.Stats.Scanned) / float64(dmatch.Seconds())
	mbps := float64(bytesScanned) / float64(dmatch.Seconds()*1000000)

	b.Logf("Benchmark using real Windows events and production detection rules")
	b.Logf("Number of rules loaded: %d", e.Count())
	b.Logf("Number of events scanned: %d", e.Stats.Scanned)
	b.Logf("Theoretical maximum engine speed: %.2f Event/s", eps)
	b.Logf("                                  %.2f MB/s", mbps)

}
