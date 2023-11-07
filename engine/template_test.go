package engine

import (
	"bytes"
	"strings"
	"testing"

	"github.com/0xrawsec/toast"
)

var (
	toReplace = map[string]string{
		"$dstprivip":  "DestinationIp ~= '{{privip}}'",
		"$suspicious": "Image ~= '{{suspicious}}'",
		"$test":       "Test ~= '({{privip}}|{{suspicious}})'",
	}
	templatesFile = `
privip = '(?i:(^127\\.)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.))'
suspicious = '(?i:(rundll32|powershell|wscript|cscript|cmd|mshta|regsvr32|certutil)\\.exe$)'
`
)

func TestLoadTemplateMap(t *testing.T) {
	tt := toast.FromT(t)

	tm := NewTemplateMap()
	tt.Log(templatesFile)
	r := bytes.NewBufferString(templatesFile)
	tt.CheckErr(tm.LoadReader(r))

	for mn, m := range toReplace {
		match := tm.ReplaceAll(m)
		_, err := parseFieldMatch(mn, match, &TypeWinevt)
		tt.CheckErr(err)
		tt.Assert(!strings.Contains(match, "{{"))
		tt.Assert(!strings.Contains(match, "}}"))
	}
}
