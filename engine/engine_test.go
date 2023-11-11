package engine

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-utils/sync/semaphore"
	"github.com/0xrawsec/golog"
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

func winEvent() *GenericEvent {
	return eventFromString(eventStr)
}

func prettyJSON(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestMatch(t *testing.T) {

	rule := `
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: [ 1 ]
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
severity: 10
`

	tt := toast.FromT(t)
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	det := evt.GetDetection()
	tt.Assert(det.Signature.Contains("ShouldMatch"))
	tt.Assert(det.IsDetection())
	tt.Assert(det.MatchCount() == 1)
	tt.Assert(det.Severity == 10)
}

func TestMatchWithEscape(t *testing.T) {

	rule := `
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: [ 1 ]
matches:
  $a: Image = 'C:\Windows\System32\DeviceCensus.exe'
  $b: Image ~= '(?i:C:\\WINDOWS\\SYSTEM32\\DEVICECENSUS.EXE)'
condition: $a and $b
severity: 10
`

	tt := toast.FromT(t)
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	det := evt.GetDetection()
	tt.Assert(det.Signature.Contains("ShouldMatch"))
	tt.Assert(det.IsDetection())
	tt.Assert(det.MatchCount() == 1)
	tt.Assert(det.Severity == 10)
}

func TestShouldNotMatch(t *testing.T) {
	tt := toast.FromT(t)
	rule := `
name: ShouldNotMatch
match-on:
  events:
    Microsoft-Windows-Sysmon/Operational: [ 4242 ]
condition:
`
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(!mr.IsDetection())
	tt.Assert(!mr.IsFiltered())
	tt.Assert(mr.IsEmpty())
	tt.Assert(evt.GetDetection() == nil)
}

func TestMatchAttck(t *testing.T) {
	rule := `
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational:
      - 1
meta:
  attack:
    - id: T666
      tactic: Blow everything up
      reference: https://attack.mitre.org/
    - id: S4242
      description: Super nasty software
      reference: https://attack.mitre.org/
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a`

	tt := toast.FromT(t)
	e := NewEngine()
	e.SetShowAttck(true)
	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	det := evt.GetDetection()
	tt.Assert(det.Signature.Contains("ShouldMatch"))
	tt.Assert(det.IsDetection())
	tt.Assert(det.MatchCount() == 1)
	tt.Assert(det.attackIds.Contains("S4242", "T666"))
}

func TestMatchByTag(t *testing.T) {
	rules := `
---
name: ShouldMatch
tags:
  - foo
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational:
      - 1
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
---
name: ShouldNotMatch
tags:
  - bar
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational:
      - 1
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
`
	tt := toast.FromT(t)
	e := NewEngine()
	e.SetFilters(nil, []string{"foo"})
	tt.CheckErr(e.LoadYamlString(rules))
	tt.Assert(e.Count() == 1)
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	det := evt.GetDetection()
	tt.Assert(det.Signature.Contains("ShouldMatch"))
	tt.Assert(det.IsDetection())
	tt.Assert(det.MatchCount() == 1)
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
	   "ProcessGuid": "B2796A13-E4BA-5880-0000-00102BC011,
	   "ProcessId": "3516",
	   "TerminalSessionId": "0",
	   "User": "NT AUTHORITY\\SYSTEM",
	   "UtcTime": "2017-01-19 16:09:30.252"
	*/

	rule := `
name: NotOrRule
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
  $b: CurrentDirectory = 'C:\Windows\system32\'
condition: '!($a or $b)'`

	tt := toast.FromT(t)
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 1)
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsEmpty())
	tt.Assert(evt.GetDetection() == nil)
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
	rule := `
name: NotAndRule
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
  $b: CurrentDirectory = 'C:\Windows\system32\'
condition: '!($a and !$b)'`

	tt := toast.FromT(t)
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 1)
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
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

	rule := `
name: ComplexRule
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
  $b: CurrentDirectory = 'C:\Windows\system32\'
  $c: CommandLine = 'C:\Windows\system32\devicecensus.exe'
  $d: Image = 'C:\Windows\System32\DeviceCensus.exe'
  $e: IntegrityLevel = 'Blop'
  $f: LogonGuid = 'B2796A13-618F-5881-0000-0020E7030000'
condition: '!($a and !$b) and ($c or ($d and !$e) ) and $f'`

	tt := toast.FromT(t)
	e := NewEngine()
	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 1)
	mr := e.Match(winEvent())
	tt.Assert(mr.IsDetection())
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

	rule := `
name: ContainerConditions
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $md5: extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in blacklist
  $sha1: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist
  $sha256: extract('SHA256=(?P<sha1>[A-F0-9]{64})', Hashes) in blacklist
condition: $md5 and $sha1 and $sha256`

	tt := toast.FromT(t)
	e := NewEngine()

	// Container update has to be done before loading rules
	e.AddToContainer("blacklist", "83514d9aaf0e168944b6d3c01110c393")
	e.AddToContainer("blacklist", "65894b0162897f2a6bb8d2eb13684bf2b451fdee")
	e.Blacklist("03324e67244312360ff089cf61175def2031be513457bb527ae0abf925e72319")
	// adding twice the same doesn't change anything
	e.Blacklist("03324e67244312360ff089cf61175def2031be513457bb527ae0abf925e72319")
	tt.Assert(e.BlacklistLen() == 3)

	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 1)
	mr := e.Match(winEvent())
	tt.Assert(mr.IsDetection())
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

	rule := `
name: ProcessCreate
params:
  filter: true
match-on:
  events:
    Microsoft-Windows-Sysmon/Operational: [1]`

	tt := toast.FromT(t)
	e := NewEngine()

	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 1)
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(!mr.IsDetection())
	tt.Assert(mr.IsFiltered())
	tt.Assert(mr.IsOnlyFiltered())
	tt.Assert(evt.GetDetection() == nil)

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

	rule := `
---
name: ProcessCreate
params:
  filter: true
match-on:
  events:
    Microsoft-Windows-Sysmon/Operational: [1]
...
---
name: SimpleRule
match-on:
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
...
`
	tt := toast.FromT(t)
	e := NewEngine()

	tt.CheckErr(e.LoadYamlString(rule))
	tt.Assert(e.Count() == 2)
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	tt.Assert(mr.IsFiltered())
	tt.Assert(!mr.IsOnlyFiltered())
	det := evt.GetDetection()
	tt.Assert(det != nil)
	tt.Assert(det.MatchCount() == 1)
}

func TestNotFiltered(t *testing.T) {
	rule := `
---
name: ProcessCreate
params:
  filter: true
match-on:
  events:
    Microsoft-Windows-Sysmon/Operational: [2]
...`
	tt := toast.FromT(t)
	e := NewEngine()

	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(!mr.IsDetection())
	tt.Assert(!mr.IsFiltered())
	tt.Assert(mr.IsEmpty())
	tt.Assert(evt.GetDetection() == nil)
}

func TestLoadDirectory(t *testing.T) {
	tt := toast.FromT(t)
	e := NewEngine()

	dir := t.TempDir()
	count := 42

	for i := 0; i < count; i++ {
		rule := fmt.Sprintf(`
---
name: ShouldMatch_%d
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
actions:
  - kill
  - kill
  - block
  - block
...
`, i)

		tt.CheckErr(os.WriteFile(filepath.Join(dir, fmt.Sprintf("rule_%d.gen", i)), []byte(rule), 0777))
	}

	tt.CheckErr(e.LoadDirectory(dir))
	tt.Assert(e.Count() == count)
	mr := e.Match(winEvent())
	tt.Assert(mr.IsDetection())
	tt.Assert(!mr.IsFiltered())
	tt.Assert(mr.MatchCount() == 42)
}

func TestActions(t *testing.T) {
	rule := `
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
actions:
  - kill
  - kill
  - block
  - block`

	tt := toast.FromT(t)
	e := NewEngine()
	e.ShowActions = true

	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	tt.Assert(evt.GetDetection().HasActions())
	tt.Assert(evt.GetDetection().Actions.Contains("kill", "block"))
	tt.Assert(evt.GetDetection().Actions.Len() == 2)
	tt.Logf(prettyJSON(evt))
}

func TestDefaultActions(t *testing.T) {
	rule := `
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a`

	tt := toast.FromT(t)
	e := NewEngine()
	e.ShowActions = true
	e.SetDefaultActions(0, 10, []string{"kill", "kill", "block", "block"})

	tt.CheckErr(e.LoadYamlString(rule))
	evt := winEvent()
	mr := e.Match(evt)
	tt.Assert(mr.IsDetection())
	tt.Assert(evt.GetDetection().HasActions())
	tt.Assert(evt.GetDetection().Actions.Contains("kill", "block"))
	tt.Assert(evt.GetDetection().Actions.Len() == 2)
}

func TestLoadContainer(t *testing.T) {
	var cfd *os.File
	var err error

	tt := toast.FromT(t)
	size := 10000
	cname := "container"
	tmp := t.TempDir()
	container := filepath.Join(tmp, "container.cont")

	cfd, err = os.Create(container)
	tt.CheckErr(err)

	for i := 0; i < size; i++ {
		cfd.WriteString(fmt.Sprintf("random.%d\n", rand.Int()))
	}

	tt.CheckErr(cfd.Close())

	e := NewEngine()
	cfd, err = os.Open(container)
	tt.CheckErr(err)

	tt.CheckErr(e.LoadContainer(cname, cfd))
	// checking container size
	tt.Assert(e.containers.Len(cname) == size)
}

func TestGetRule(t *testing.T) {
	collect := func(c chan string) (out []string) {
		for s := range c {
			out = append(out, s)
		}
		return
	}

	tt := toast.FromT(t)

	rule := `
---
name: ShouldMatch
match-on:
  log-type: winevt
  events:
    Microsoft-Windows-Sysmon/Operational: []
matches:
  $a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'
condition: $a
...`

	e := NewEngine()
	e.SetDumpRaw(true)

	tt.CheckErr(e.LoadYamlString(rule))

	tt.Assert(len(collect(e.GetRawRule("Should"))) == 1)

	tt.Assert(e.GetRawRuleByName("ShouldMatch") != "")
	tt.Assert(e.GetCompRuleByName("ShouldMatch") != nil)

	tt.Assert(e.GetRawRuleByName("XYZ") == "")
	tt.Assert(e.GetCompRuleByName("XYZ") == nil)

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
		"Channels" : ["Microsoft-Windows-Sysmon/Operational"]
		
		},
	"Condition": ""
	}`

	e := NewEngine()

	tt.Assert(e.LoadJsonString(rule) != nil)
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

	rule := `
---
name: ShouldMatch
match-on:
  events:
    kunai: []
matches:
  $a: exe/file = '/usr/bin/ping'
  $b: /data/exe/md5 = '2d57c5245652e40bbf51edaaa3be65bd'
condition: $a and $b
...`

	e := NewEngine()

	tt.CheckErr(e.LoadYamlString(rule))
	evt := eventFromString(event)
	mr := e.Match(evt)
	tt.Logf("names: %s", mr.MatchesSlice())
	tt.Assert(mr.MatchCount() > 0)
	tt.Logf(prettyJSON(evt))
}

/////////////////////////////// Benchmarks /////////////////////////////////////

func BenchmarkEngine(b *testing.B) {
	bench(b, 1)
}

func BenchmarkEngineParallel(b *testing.B) {
	bench(b, uint64(runtime.NumCPU()))
}

func bench(b *testing.B, jobs uint64) {
	var err error
	var fd *os.File
	var r *gzip.Reader
	var bytesScanned uint64

	Logger.Level = golog.LevelDisable

	// Enable CPU profiling
	f, err := os.Create("/tmp/cpu.pprof")
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	defer f.Close()

	loops := 5
	events := make([]GenericEvent, 0)

	eventsFile := "./test/data/events.json.gz"
	rulePath := "./test/data/compiled.gen"
	e := NewEngine()

	start := time.Now()
	// loading rules into engine
	if err := e.LoadFile(rulePath); err != nil {
		b.Errorf("Loading failed: %s", err)
		b.FailNow()
	}

	for i := 1; i < 3; i++ {
		for _, r := range e.rules {
			r.Name = fmt.Sprintf("%s-%d", r.Name, i)
			if err := e.addRule(r); err != nil {
				b.Errorf("AddRule failed: %s", err)
				b.FailNow()
			}
		}
	}
	loadTime := time.Since(start)

	if e.Count() == 0 {
		b.Errorf("No rule loaded")
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

	start = time.Now()
	// start rule matching profiling
	pprof.StartCPUProfile(f)
	wg := sync.WaitGroup{}
	sem := semaphore.New(jobs)
	for i := 0; i < loops; i++ {
		wg.Add(1)
		sem.Acquire()
		go func() {
			for _, evt := range events {
				e.Match(evt)
			}
			wg.Done()
			sem.Release()
		}()
	}
	wg.Wait()
	// stop rule matching profiling
	pprof.StopCPUProfile()
	scanTime := time.Since(start)

	// statistics
	// we have to multiply the number of bytes scanned by the
	// number of loops we have done
	bytesScanned *= uint64(loops)
	eps := float64(e.Stats.Scanned) / float64(scanTime.Seconds())
	mbps := float64(bytesScanned) / float64(scanTime.Seconds()*1000000)

	cntRulesEn, cntRulesDis := 0, 0
	for _, r := range e.rules {
		if r.Disabled {
			cntRulesDis++
			continue
		}
		cntRulesEn++
	}

	b.Logf("Benchmark using real Windows events and production detection rules")
	b.Logf("Number of scanning jobs: %d", jobs)
	b.Logf("Number of rules loaded: %d (enabled=%d, disabled=%d) in %s", e.Count(), cntRulesEn, cntRulesDis, loadTime)
	b.Logf("Number of events scanned: %d in %s", e.Stats.Scanned, scanTime)
	b.Logf("Number of cached events: %d => %.2f%%", e.Stats.Cached, float64(e.Stats.Cached)*100/float64(e.Stats.Scanned))
	b.Logf("Number of detections: %d => %.2f%%", e.Stats.Detections, float64(e.Stats.Detections)*100/float64(e.Stats.Scanned))
	b.Logf("Theoretical average engine scanning speed: %.2f events/s", eps)
	b.Logf("                                           %.2f MBs/s", mbps)
}
