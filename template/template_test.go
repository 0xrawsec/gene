package template

import (
	"testing"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/toast"
)

// we make sure rule Template compiles properly
func TestTemplate(t *testing.T) {
	tt := toast.FromT(t)

	e := engine.NewEngine()

	tt.CheckErr(e.LoadYamlString(RuleTemplate))
}
