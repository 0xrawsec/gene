package engine

import (
	"fmt"
	"strings"
)

const (
	xpathSep = "/"
)

var (
	eventIDPath    = Path("/Event/System/EventID")
	channelPath    = Path("/Event/System/Channel")
	computerPath   = Path("/Event/System/Computer")
	systemTimePath = Path("/Event/System/TimeCreated/SystemTime")

	// GeneInfoPath path to the Gene information in a modified event
	GeneInfoPath = Path("/Event/GeneInfo")
)

type ErrItemNotFound struct {
	p XPath
}

func (e *ErrItemNotFound) Error() string {
	return fmt.Sprintf("Item at path %s%s not found", xpathSep, strings.Join(e.p, xpathSep))
}

type XPath []string

func Path(p string) XPath {
	san := strings.Trim(p, xpathSep)
	return strings.Split(san, xpathSep)
}

func (p XPath) Last() string {
	if len(p) > 0 {
		return p[len(p)-1]
	}
	return ""
}

func (p XPath) String() string {
	return fmt.Sprintf("/%s", strings.Join(p, xpathSep))
}

func (p XPath) StartsWith(start XPath) bool {
	if len(p) > 0 && len(p) >= len(start) {
		return XPath(p[:len(start)]).Equal(start)
	}
	return false
}

// Equal is an optimized equality check between two paths
func (p XPath) Equal(other XPath) bool {
	if len(p) != len(other) {
		return false
	}

	// Do a reverse equality as beginning of
	// path are very likely the same
	for i := len(p) - 1; i != -1; i-- {
		// element of the path struct
		p := p[i]
		// element of the path to compare with
		o := other[i]

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
