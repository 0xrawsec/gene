package reducer

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/0xrawsec/gene/globals"

	"github.com/0xrawsec/golang-utils/datastructs"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/stats"
)

//////////////////////////// Reducer ////////////////////////////////

// ReducedStats structrure definition
type ReducedStats struct {
	Identifier      string         `json:"identifier"`
	CntAlerts       int            `json:"alert-count"`
	CntBySig        map[string]int `json:"count-by-signature"`
	UniqSigs        []string       `json:"signatures"`
	Techniques      []string       `json:"techniques"`
	Tactics         []string       `json:"tactics"`
	TotalSigs       int            `json:"signature-count"`
	SumAlertCrit    int            `json:"sum-alert-criticality"`
	AvgAlertCrit    float64        `json:"avg-alert-criticality"`
	StdDevAlertCrit float64        `json:"std-dev-alert-criticality"`
	SumRuleCrit     int            `json:"sum-rule-criticality"`
	AvgSigCrit      float64        `json:"avg-signature-criticality"`
	StdDevSigCrit   float64        `json:"std-dev-signature-criticality"`
	SigDiv          float64        `json:"signature-diversity"`
	CntUniqSigs     int            `json:"count-uniq-signatures"`
	// signature criticality metric, the higher it is the more attention should be given to the report
	CntUniqByAvgCritBySig int `json:"signature-criticality-metric"`
	// alert criticality metric, the higher it is the more attention should be given to the report
	AvgAlertCritBySigDiv int `json:"alert-criticality-metric"`
	// aggregated metric used to sort statistic reports between them. Higher the score higher the priority
	Score      int       `json:"score"`
	StartTime  time.Time `json:"start-time"`
	MedianTime time.Time `json:"median-time"`
	StopTime   time.Time `json:"stop-time"`
	techniques datastructs.SyncedSet
	tactics    datastructs.SyncedSet
	sigCrits   []float64
	alertCrits []float64
	eng        *engine.Engine
}

// NewReducedStats structure
func NewReducedStats(e *engine.Engine, identifier string) *ReducedStats {
	return &ReducedStats{Identifier: identifier,
		CntBySig:   make(map[string]int),
		UniqSigs:   make([]string, 0),
		tactics:    datastructs.NewSyncedSet(),
		techniques: datastructs.NewSyncedSet(),
		sigCrits:   make([]float64, 0),
		alertCrits: make([]float64, 0),
		eng:        e}
}

// Copy returns a new copy of structure
func (rs *ReducedStats) Copy() *ReducedStats {
	new := *rs
	return &new
}

// Update ReducedStats with data
func (rs *ReducedStats) Update(t time.Time, matches []string) {
	evtCrit := 0

	// Set StartTime
	if t.Before(rs.StartTime) || rs.StartTime.IsZero() {
		rs.StartTime = t
	}

	// Set StopTime
	if t.After(rs.StopTime) {
		rs.StopTime = t
	}

	for _, m := range matches {
		rs.CntBySig[m]++
		rs.TotalSigs++

		if r := rs.eng.GetCRuleByName(m); r != nil {
			for _, ttp := range r.Attack {
				rs.techniques.Add(ttp.ID)
				rs.tactics.Add(ttp.Tactic)
			}

			// don't take informative rules into account
			if r.Criticality != 0 {
				rs.SumRuleCrit += r.Criticality
				evtCrit += r.Criticality
				rs.sigCrits = append(rs.sigCrits, float64(r.Criticality))
			}
		}

	}
	if evtCrit > globals.CriticalityBound {
		rs.SumAlertCrit += globals.CriticalityBound
		rs.alertCrits = append(rs.alertCrits, float64(globals.CriticalityBound))
	} else {
		rs.SumAlertCrit += evtCrit
		rs.alertCrits = append(rs.alertCrits, float64(evtCrit))
	}

	rs.CntAlerts++
}

// Finalize the computation of the statistics
func (rs *ReducedStats) Finalize(cntSigs int) {

	// process techniques
	for _, i := range *rs.techniques.List() {
		technique := i.(string)
		rs.Techniques = append(rs.Techniques, technique)
	}

	// process tactics
	for _, i := range *rs.tactics.List() {
		tactic := i.(string)
		rs.Tactics = append(rs.Tactics, tactic)
	}

	// compute alerts statistics
	rs.AvgAlertCrit = stats.Truncate(float64(rs.SumAlertCrit)/float64(rs.CntAlerts), 2)
	rs.StdDevAlertCrit = stats.Truncate(stats.StdDev(rs.alertCrits), 2)

	// compute signature statistics
	rs.AvgSigCrit = stats.Truncate(float64(rs.SumRuleCrit)/float64(rs.TotalSigs), 2)
	// Compute Standard Dev
	rs.StdDevSigCrit = stats.Truncate(stats.StdDev(rs.sigCrits), 2)
	rs.CntUniqSigs = len(rs.CntBySig)
	rs.CntUniqByAvgCritBySig = rs.CntUniqSigs * int(math.Round(rs.AvgSigCrit))

	// The diversity is relative to the number of signatures observed
	// accross the dataset
	rs.SigDiv = stats.Truncate(float64(rs.CntUniqSigs)*100/float64(cntSigs), 2)
	rs.AvgAlertCritBySigDiv = int(math.Round((rs.AvgAlertCrit * rs.SigDiv)))

	rs.Score = rs.AvgAlertCritBySigDiv + rs.CntUniqByAvgCritBySig

	for s := range rs.CntBySig {
		rs.UniqSigs = append(rs.UniqSigs, s)
	}

	rs.MedianTime = rs.StartTime.Add((rs.StopTime.Sub(rs.StartTime)) / 2)
}

func (rs ReducedStats) String() string {
	//rs.Finalize()
	return string(evtx.ToJSON(rs))
}

// Reducer structure to store statistics about several machines
type Reducer struct {
	sync.RWMutex
	e        *engine.Engine
	m        map[string]*ReducedStats
	uniqSigs datastructs.SyncedSet
}

// NewReducer creates a new Reducer structure
func NewReducer(e *engine.Engine) *Reducer {
	return &Reducer{e: e,
		m:        make(map[string]*ReducedStats),
		uniqSigs: datastructs.NewSyncedSet()}
}

// Update a ReducedStats stored in Reducer with data
func (r *Reducer) Update(t time.Time, identifier string, matches []string) {
	r.Lock()
	defer r.Unlock()

	if _, ok := r.m[identifier]; !ok {
		r.m[identifier] = NewReducedStats(r.e, identifier)
	}

	for _, sig := range matches {
		r.uniqSigs.Add(sig)
	}

	rs := r.m[identifier]
	rs.Update(t, matches)
}

// ReduceCopy reduces alerts of a single computer and returns a copy of ReducedStats
func (r *Reducer) ReduceCopy(identifier string) (crs *ReducedStats) {
	r.RLock()
	defer r.RUnlock()
	if rs, ok := r.m[identifier]; ok {
		crs = rs.Copy()
		crs.Finalize(r.uniqSigs.Len())
	}
	return

}

// Reset ReducedStats according to its identifier
func (r *Reducer) Reset(identifier string) {
	r.m[identifier] = NewReducedStats(r.e, identifier)
}

// CountUniqSigs counts all the uniq signatures seen in the reduced stats
func (r *Reducer) CountUniqSigs() int {
	return r.uniqSigs.Len()
}

// Print prints out all the informations stored in the Reducer
func (r *Reducer) Print() {
	r.RLock()
	defer r.RUnlock()
	//cnt := r.CountUniqSigs()
	for computer := range r.m {
		//r.m[computer].Finalize(cnt)
		//fmt.Println(r.m[computer])
		fmt.Println(r.ReduceCopy(computer))
	}
}
