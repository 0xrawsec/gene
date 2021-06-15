package rules

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/readers"
	"github.com/0xrawsec/golang-utils/regexp/submatch"
)

var (
	templateRegexp       = regexp.MustCompile(`^\s*(?P<name>[^\s]+)\s*:\s*(?P<value>'.*?'\s*$)`)
	templateRegexpHelper = submatch.NewHelper(templateRegexp)
)

//Template structure definition
type Template struct {
	Name  string `regexp:"name"`
	Value string `regexp:"value"`
}

//ParseTemplate parses a template string
func ParseTemplate(tplString string) (tpl Template, err error) {
	if !templateRegexp.MatchString(tplString) {
		return tpl, fmt.Errorf("Syntax error in \"%s\"", tplString)
	}
	templateRegexpHelper.Prepare([]byte(tplString))
	err = templateRegexpHelper.Unmarshal(&tpl)
	tpl.Value = strings.Trim(tpl.Value, "'")
	return
}

//Replace function
func (t *Template) Replace(s string) (new string) {
	return strings.Replace(s, fmt.Sprintf("{{%s}}", t.Name), t.Value, -1)
}

////////////////////////////////// Template Map ////////////////////////////////

//TemplateMap structure
type TemplateMap struct {
	*datastructs.SyncedMap
}

//NewTemplateMap creates a new TemplateMap structure
func NewTemplateMap() *TemplateMap {
	tm := TemplateMap{datastructs.NewSyncedMap()}
	return &tm
}

//LoadReader loads templates from a reader, one template per line
//If the line starts with #, it is considered as comment and is not parsed
func (tm *TemplateMap) LoadReader(r io.Reader) error {
	for line := range readers.Readlines(r) {
		tpl, err := ParseTemplate(string(line))
		if err != nil && !(len(line) == 0 || line[0] == '#') {
			return err
		}
		tm.AddTemplate(&tpl)
	}
	return nil
}

//AddTemplate adds a new template to the TemplateMap
func (tm *TemplateMap) AddTemplate(t *Template) {
	tm.Add(t.Name, t)
}

//GetTemplate return the template associated to the name
func (tm *TemplateMap) GetTemplate(name string) (ok bool, tpl *Template) {
	val, ok := tm.Get(name)
	return ok, val.(*Template)
}

//ReplaceAll replaces all templates in string and return the new string
func (tm *TemplateMap) ReplaceAll(s string) (new string) {
	new = s
	for name := range tm.Keys() {
		ok, tpl := tm.GetTemplate(name.(string))
		if ok {
			new = tpl.Replace(new)
		} else {
			panic("This should never happen")
		}
	}
	return
}
