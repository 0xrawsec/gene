package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
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
	event       = make(evtx.GoEvtxMap)
	bigRuleFile = "./data/1000rules.json"
)

var (
	ErrBufferOutOfBounds = fmt.Errorf("Buffer out of bound")
)

type SeekBuffer struct {
	i    int
	buff []byte
}

func NewSeekBuffer(b []byte) *SeekBuffer {
	sb := &SeekBuffer{}
	sb.buff = make([]byte, len(b))
	copy(sb.buff, b)
	return sb
}

func (sb *SeekBuffer) Read(p []byte) (n int, err error) {
	if sb.i+len(p) < sb.Len() {
		n = copy(p, sb.buff[sb.i:sb.i+len(p)])
		sb.i += n
		return n, nil
	}
	n = copy(p, sb.buff[sb.i:])
	sb.i += n
	return n, io.EOF
}

func (sb *SeekBuffer) Len() int {
	return len(sb.buff)
}

func (sb *SeekBuffer) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case os.SEEK_CUR:
		if sb.i+int(offset) <= sb.Len() {
			sb.i += int(offset)
			break
		}
		return 0, ErrBufferOutOfBounds
	case os.SEEK_SET:
		if int(offset) <= sb.Len() && offset >= 0 {
			sb.i = int(offset)
			break
		}
		return 0, ErrBufferOutOfBounds
	case os.SEEK_END:
		if sb.Len()-int(offset) > 0 {
			sb.i = sb.Len() - int(offset)
			break
		}
		return 0, ErrBufferOutOfBounds
	}
	return int64(sb.i), nil
}

func init() {
	err := json.Unmarshal([]byte(eventStr), &event)
	if err != nil {
		panic(err)
	}
}

func prettyJSON(i interface{}) string {
	b, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(b)
}

func openEvtx(path string) *evtx.File {
	f, err := evtx.OpenDirty(path)
	if err != nil {
		panic(err)
	}
	return &f
}

func TestLoad(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`
	e := NewEngine(false)
	if err := e.LoadReader(NewSeekBuffer([]byte(rule))); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
}

func TestMatch(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine(false)
	if err := e.LoadReader(NewSeekBuffer([]byte(rule))); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _ := e.Match(&event); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestMatchAttck(t *testing.T) {
	rule := `{
	"Name": "ShouldMatch",
	"Meta": {
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
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
		]	
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}`

	e := NewEngine(false)
	e.SetShowAttck(true)
	if err := e.LoadReader(NewSeekBuffer([]byte(rule))); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	if m, _ := e.Match(&event); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(prettyJSON(event))
	}
}

func TestMatchByTag(t *testing.T) {
	rules := `{
	"Name": "ShouldMatch",
	"Tags": ["foo"],
	"Meta": {
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}
	`

	e := NewEngine(false)
	tags := []string{"foo"}
	e.SetFilters([]string{}, tags)

	if err := e.LoadReader(NewSeekBuffer([]byte(rules))); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())

	if m, _ := e.Match(&event); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}

}

func TestSimpleRule(t *testing.T) {
	rule := `{
	"Name": "SimpleRule",
	"Meta": {
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'"
		],
	"Condition": "$a"
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Engine loaded %d rule", e.Count())
	if m, _ := e.Match(&event); len(m) == 0 {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'"
		],
	"Condition": "!($a or $b)"
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	// The match should fail
	if m, _ := e.Match(&event); len(m) != 0 {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'"
		],
	"Condition": "!($a and !$b)"
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	// The match should fail
	if m, _ := e.Match(&event); len(m) == 0 {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$a: Hashes ~= 'SHA1=65894B0162897F2A6BB8D2EB13684BF2B451FDEE,'",
		"$b: CurrentDirectory = 'C:\\Windows\\system32\\'",
		"$c: CommandLine = 'C:\\Windows\\system32\\devicecensus.exe'",
		"$d: Image = 'C:\\Windows\\System32\\DeviceCensus.exe'",
		"$e: IntegrityLevel = 'Blop'",
		"$f: LogonGuid = 'B2796A13-618F-5881-0000-0020E7030000'"
		],
	"Condition": "!($a and !$b) and ($c or ($d and !$e) ) and !$f"
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if m, _ := e.Match(&event); len(m) == 0 {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"]
		},
	"Matches": [
		"$md5: extract('MD5=(?P<md5>[A-F0-9]{32})', Hashes) in blacklist",
		"$sha1: extract('SHA1=(?P<sha1>[A-F0-9]{40})', Hashes) in blacklist",
		"$sha256: extract('SHA256=(?P<sha1>[A-F0-9]{64})', Hashes) in blacklist"
		],
	"Condition": "$md5 and $sha1 and $sha256"
	}
	`
	e := NewEngine(false)
	// Container update has to be done before loading rules
	e.AddToContainer("blacklist", "83514d9aaf0e168944b6d3c01110c393")
	e.AddToContainer("blacklist", "65894b0162897f2a6bb8d2eb13684bf2b451fdee")
	e.AddToContainer("blacklist", "03324e67244312360ff089cf61175def2031be513457bb527ae0abf925e72319")
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if m, _ := e.Match(&event); len(m) == 0 {
		t.Fail()
	} else {
		t.Log(m)
	}
}

func TestFiltered(t *testing.T) {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"EventIDs": [1],
		"Filter": true
		},
	"Matches": [],
	"Condition": ""
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if _, _, filtered := e.MatchOrFilter(&event); filtered {
		t.Log("Event correctly filtered")
		t.Logf("%s", prettyJSON(event))
	} else {
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
		"Channels": ["Microsoft-Windows-Sysmon/Operational"],
		"EventIDs": [2],
		"Filter": true
		},
	"Matches": [],
	"Condition": ""
	}
	`
	e := NewEngine(false)
	err := e.LoadReader(NewSeekBuffer([]byte(rule)))
	if err != nil {
		t.Fail()
		t.Log(err)
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
	// The match should fail
	if _, _, filtered := e.MatchOrFilter(&event); !filtered {
		t.Log("Event not filtered")
	} else {
		t.Fail()
	}
}

func TestLoadDirectory(t *testing.T) {
	e := NewEngine(false)
	err := e.LoadDirectory("./")
	if err != nil {
		t.Errorf("Failed to load rules in directory: %s", err)
	}
	t.Logf("Loaded %d rules", e.Count())
}

/////////////////////////////// Benchmarks /////////////////////////////////////

func BenchmarkLoadThousand(b *testing.B) {
	e := NewEngine(false)
	if err := e.Load(bigRuleFile); err != nil {
		b.Logf("Loading failed: %s", err)
		b.FailNow()
	}
	b.Logf("Engine loaded %d rules", e.Count())

}
