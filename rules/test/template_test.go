package main

import (
	"bytes"
	"testing"

	"github.com/0xrawsec/gene/rules"
)

var (
	templates = []string{
		`privip: '(?i:(^127\\.)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.))'`,
		`suspicious: '(?i:(rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|certutil)\\.exe$)'`,
	}
	toReplace = []string{
		"$dstprivip: DestinationIp ~= '{{privip}}'",
		"$suspicious: Image ~= '{{suspicious}}'",
		"$test: Test ~= '({{privip}}|{{suspicious}})'",
	}
	templatesFile = `
privip: '(?i:(^127\\.)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.))'
suspicious: '(?i:(rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|certutil)\\.exe$)'
`
)

func TestParseTemplate(t *testing.T) {
	for _, match := range toReplace {
		for _, tplStr := range templates {
			tpl, err := rules.ParseTemplate(tplStr)
			if err != nil {
				t.Log(err)
				t.Fail()
			}
			match = tpl.Replace(match)
		}
		_, err := rules.ParseFieldMatch(match)
		if err != nil {
			t.Errorf("Failed to compile \"%s\": %s", match, err)
			t.Fail()
		} else {
			t.Logf("Successfully compiled: %s", match)
		}
	}
}

func TestTemplateMap(t *testing.T) {
	tm := rules.NewTemplateMap()
	for _, tplStr := range templates {
		tpl, err := rules.ParseTemplate(tplStr)
		if err != nil {
			t.Error(err)
			t.Fail()
		}
		tm.AddTemplate(&tpl)
	}

	for _, s := range toReplace {
		match := tm.ReplaceAll(s)
		_, err := rules.ParseFieldMatch(match)
		if err != nil {
			t.Errorf("Failed to compile \"%s\": %s", match, err)
			t.Fail()
		} else {
			t.Logf("Successfully compiled: %s", match)
		}
	}
}

func TestLoadTemplateMap(t *testing.T) {
	tm := rules.NewTemplateMap()
	t.Log(templatesFile)
	r := bytes.NewBufferString(templatesFile)
	err := tm.LoadReader(r)
	if err != nil {
		t.Errorf("Error loading template file: %s", err)
		t.Fail()
	}

	for _, s := range toReplace {
		match := tm.ReplaceAll(s)
		_, err := rules.ParseFieldMatch(match)
		if err != nil {
			t.Errorf("Failed to compile \"%s\": %s", match, err)
			t.Fail()
		} else {
			t.Logf("Successfully compiled: %s", match)
		}
	}
}
