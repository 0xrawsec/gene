package engine

import (
	"bytes"
	"testing"
)

var (
	toReplace = []string{
		"$dstprivip: DestinationIp ~= '{{privip}}'",
		"$suspicious: Image ~= '{{suspicious}}'",
		"$test: Test ~= '({{privip}}|{{suspicious}})'",
	}
	templatesFile = `
privip = '(?i:(^127\\.)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.))'
suspicious = '(?i:(rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|certutil)\\.exe$)'
`
)

func TestLoadTemplateMap(t *testing.T) {
	tm := NewTemplateMap()
	t.Log(templatesFile)
	r := bytes.NewBufferString(templatesFile)
	err := tm.LoadReader(r)
	if err != nil {
		t.Errorf("Error loading template file: %s", err)
		t.Fail()
	}

	for _, s := range toReplace {
		match := tm.ReplaceAll(s)
		_, err := ParseFieldMatch(match, &TypeWinevt)
		if err != nil {
			t.Errorf("Failed to compile \"%s\": %s", match, err)
			t.Fail()
		} else {
			t.Logf("Successfully compiled: %s", match)
		}
	}
}
