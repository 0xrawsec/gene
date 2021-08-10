package engine

import (
	"fmt"
	"io"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/pelletier/go-toml"
)

//Template structure definition
type Template struct {
	Name  string
	Value string
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
func (tm *TemplateMap) LoadReader(r io.Reader) (err error) {
	var tree *toml.Tree

	if tree, err = toml.LoadReader(r); err != nil {
		return
	}

	for name, value := range tree.ToMap() {
		if regexp, ok := value.(string); ok {
			tm.AddTemplate(&Template{name, regexp})
		} else {
			return fmt.Errorf("%s template is not a string", name)
		}
	}

	return
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
