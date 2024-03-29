package engine

import (
	"errors"
	"fmt"
	"strings"
)

const (
	xpathSep = "/"
)

var (
	systemTimePath = Path("/Event/System/TimeCreated/SystemTime")

	eventDataPath = path("/Event/EventData")

	// GeneInfoPath path to the Gene information in a modified event
	GeneInfoPath = Path("/Event/GeneInfo")

	ErrItemNotFound = errors.New("item not found")
)

type XPath struct {
	Path  []string
	Flags struct {
		EventDataField bool
		UserDataField  bool
	}
}

func splitPath(p string) []string {
	// if we want to have a cutset instead of a single character
	return strings.FieldsFunc(p, func(c rune) bool {
		return c == '/'
	})
}

func path(p string) (x *XPath) {
	san := strings.Trim(p, xpathSep)
	x = &XPath{Path: splitPath(san)}
	return x
}

func IsAbsoluteXPath(p string) bool {
	return strings.HasPrefix(p, xpathSep)
}

func Path(p string) (x *XPath) {
	x = path(p)
	x.initFlags()
	return
}

func (p *XPath) initFlags() {
	if p.Get(0) != "Event" {
		return
	}

	switch p.Get(1) {
	case "EventData":
		p.Flags.EventDataField = true
	case "UserData":
		p.Flags.UserDataField = true
	}
}

func (p *XPath) Get(i int) string {
	if i >= 0 && i < len(p.Path) {
		return p.Path[i]
	}
	return ""
}

func (p *XPath) Last() string {
	if len(p.Path) > 0 {
		return p.Path[len(p.Path)-1]
	}
	return ""
}

func (p *XPath) Merge(other *XPath) *XPath {
	new := XPath{Path: append(p.Path[:], other.Path...)}
	new.initFlags()
	return &new
}

func (p *XPath) Append(s string) *XPath {
	new := XPath{Path: append(p.Path[:], s)}
	new.initFlags()
	return &new
}

func (p *XPath) String() string {
	return fmt.Sprintf("/%s", strings.Join(p.Path, xpathSep))
}

func (p *XPath) StartsWith(start *XPath) bool {
	if len(p.Path) > 0 && len(p.Path) >= len(start.Path) {
		tmp := XPath{Path: p.Path[:len(start.Path)]}
		return tmp.Equal(start)
	}
	return false
}

// Equal is an optimized equality check between two paths
func (p *XPath) Equal(other *XPath) bool {
	if len(p.Path) != len(other.Path) {
		return false
	}

	// Do a reverse equality as beginning of
	// path are very likely the same
	for i := len(p.Path) - 1; i != -1; i-- {
		// element of the path struct
		p := p.Path[i]
		// element of the path to compare with
		o := other.Path[i]

		// if comparable elements are of different size
		// path cannot be equal
		if len(p) != len(o) {
			return false
		}
		// we are sure we compare strings of the same size
		for k := len(p) - 1; k != -1; k-- {
			if p[k] != o[k] {
				return false
			}
		}
	}

	return true
}

func (p *XPath) Len() int {
	return len(p.Path)
}
