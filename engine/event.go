package engine

import (
	"fmt"
	"strconv"
	"time"
)

type Event interface {
	Format() *LogType
	Set(*XPath, interface{}) error
	SetDetection(d *Detection)
	Get(*XPath) (interface{}, bool)
	GetDetection() *Detection
	Channel() string
	Computer() string
	EventID() int64
	Timestamp() time.Time
}

func EventGetString(evt Event, p *XPath) (string, bool) {
	if i, ok := evt.Get(p); ok {
		switch i.(type) {
		case string:
			return i.(string), true
		default:
			return fmt.Sprintf("%v", i), true
		}
	}
	return "", false
}

type GenericEvent map[string]interface{}

func (g GenericEvent) Set(p *XPath, new interface{}) error {
	if len(p.Path) > 0 {
		i := g[p.Path[0]]
		if len(p.Path) == 1 {
			g[(p.Path)[0]] = new
			return nil
		}
		switch i.(type) {
		case map[string]interface{}:
			ng := GenericEvent(i.(map[string]interface{}))
			np := &XPath{Path: p.Path[1:]}
			return ng.Set(np, new)
		}

	}

	return fmt.Errorf("%w at path %s", ErrItemNotFound, p)
}

func (e GenericEvent) Get(p *XPath) (interface{}, bool) {
	if len(p.Path) > 0 {
		if i, ok := e[p.Path[0]]; ok {
			if len(p.Path) == 1 {
				return i, true
			}
			switch i.(type) {
			case map[string]interface{}:
				ne := GenericEvent(i.(map[string]interface{}))
				np := &XPath{Path: p.Path[1:]}
				return ne.Get(np)
			}
		}
	}
	return nil, false
}

func (g GenericEvent) SetDetection(d *Detection) {
	p := g.Format().GeneInfo
	g.Set(p, d)
}

func (g GenericEvent) GetDetection() *Detection {
	p := g.Format().GeneInfo
	if i, ok := g.Get(p); ok {
		if d, ok := i.(*Detection); ok {
			return d
		}
	}
	return nil
}

func (g GenericEvent) Channel() string {
	p := g.Format().Channel
	if ch, ok := EventGetString(g, p); ok {
		return ch
	}
	return ""
}

func (g GenericEvent) Computer() string {
	p := g.Format().Hostname
	if comp, ok := EventGetString(g, p); ok {
		return comp
	}
	return ""
}

func (g GenericEvent) EventID() (id int64) {
	var err error

	p := g.Format().EventID
	if s, ok := EventGetString(g, p); ok {
		if id, err = strconv.ParseInt(s, 0, 32); err == nil {
			return
		}
	}
	return
}

func (g GenericEvent) Timestamp() time.Time {
	p := g.Format().Timestamp
	if sts, ok := EventGetString(g, p); ok {
		if ts, err := time.Parse(time.RFC3339Nano, sts); err == nil {
			return ts
		}
	}
	return time.Time{}
}

func (g GenericEvent) Format() *LogType {
	// should be in any windows event
	if _, ok := g.Get(systemTimePath); ok {
		return &TypeWinevt
	}
	return &TypeKunai
}
