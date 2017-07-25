package main

import (
	"engine"
	"testing"

	"github.com/0xrawsec/golang-evtx/evtx"
)

var (
	singleRuleFile = "./data/rule1.json"
	bigRuleFile    = "./data/1000rules.json"
	evtxFile       = "sysmon.evtx"
)

func openEvtx(path string) evtx.File {
	f, err := evtx.New(path)
	if err != nil {
		panic(err)
	}
	return f
}

func TestLoad(t *testing.T) {
	e := engine.NewEngine()
	if err := e.Load(singleRuleFile); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())
}

func TestMatch(t *testing.T) {
	e := engine.NewEngine()
	if err := e.Load(singleRuleFile); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())

	f := openEvtx(evtxFile)
	for event := range f.FastEvents() {
		m, c := e.Match(event)
		if len(m) > 0 {
			t.Logf("matches:%v criticality:%d", m, c)
		}
	}
}

func TestMatchByTag(t *testing.T) {
	e := engine.NewEngine()
	if err := e.Load(singleRuleFile); err != nil {
		t.Logf("Loading failed: %s", err)
		t.FailNow()
	}
	t.Logf("Successfuly loaded %d rules", e.Count())

	f := openEvtx(evtxFile)
	tags := []string{"foo"}
	for event := range f.FastEvents() {
		m, c := e.MatchByTag(&tags, event)
		if len(m) > 0 {
			t.Logf("matches:%v criticality:%d", m, c)
			t.Logf(string(evtx.ToJSON(event)))
		}
	}
}

func BenchmarkLoadThousand(b *testing.B) {
	e := engine.NewEngine()
	if err := e.Load(bigRuleFile); err != nil {
		b.Logf("Loading failed: %s", err)
		b.FailNow()
	}
	b.Logf("Engine loaded %d rules", e.Count())

}
