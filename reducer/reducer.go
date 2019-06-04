package reducer

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/log"

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/stats"
)

//////////////////////////// Reducer ////////////////////////////////

// ReducedStats structrure definition
type ReducedStats struct {
	Computer              string
	CntEvents             int
	CntBySig              map[string]int
	UniqSigs              []string `json:"Signatures"`
	SumRuleCrit           int
	SumEvtCrit            int
	TotalSigs             int
	AvgEvtsCrit           float64
	AvgSigCrit            float64
	StdDevCrit            float64
	SigDiv                float64 `json:"SignatureDiversity"`
	CntUniqSigs           int
	CntUniqByAvgCritBySig int     `json:"AugmentedSigCriticality"`
	AvgEvtCritBySigDiv    float64 `json:"WeightedEventsCriticality"`
	StartTime             time.Time
	MedianTime            time.Time
	StopTime              time.Time
	sigCrits              []float64
	evtCrits              []float64
	eng                   *engine.Engine
}

// NewReducedStats structure
func NewReducedStats(e *engine.Engine, computer string) *ReducedStats {
	return &ReducedStats{Computer: computer,
		CntBySig: make(map[string]int),
		UniqSigs: make([]string, 0),
		sigCrits: make([]float64, 0),
		eng:      e}
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
			// don't take informative rules into account
			if r.Criticality != 0 {
				rs.SumRuleCrit += r.Criticality
				evtCrit += r.Criticality
				rs.sigCrits = append(rs.sigCrits, float64(r.Criticality))
			}
		}

	}
	if evtCrit > 10 {
		rs.SumEvtCrit += 10
	} else {
		rs.SumEvtCrit += evtCrit
	}

	rs.CntEvents++
}

// Finalize the computation of the statistics
func (rs *ReducedStats) Finalize(cntSigs int) {
	rs.AvgEvtsCrit = stats.Truncate(float64(rs.SumEvtCrit)/float64(rs.CntEvents), 2)

	rs.AvgSigCrit = stats.Truncate(float64(rs.SumRuleCrit)/float64(rs.TotalSigs), 2)
	rs.CntUniqSigs = len(rs.CntBySig)
	rs.CntUniqByAvgCritBySig = rs.CntUniqSigs * int(math.Round(rs.AvgSigCrit))

	// Compute Standard Dev
	rs.StdDevCrit = stats.Truncate(stats.StdDev(rs.sigCrits), 2)

	// The diversity is relative to the number of signatures observed
	// accross the dataset
	rs.SigDiv = stats.Truncate(float64(rs.CntUniqSigs)*100/float64(cntSigs), 2)
	rs.AvgEvtCritBySigDiv = math.Round((rs.AvgEvtsCrit * rs.SigDiv))

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
	e *engine.Engine
	m map[string]*ReducedStats
}

// NewReducer creates a new Reducer structure
func NewReducer(e *engine.Engine) *Reducer {
	return &Reducer{e: e, m: make(map[string]*ReducedStats)}
}

// Update a ReducedStats stored in Reducer with data
func (r *Reducer) Update(t time.Time, computer string, matches []string) {
	r.Lock()
	if _, ok := r.m[computer]; !ok {
		r.m[computer] = NewReducedStats(r.e, computer)
	}
	rs := r.m[computer]
	rs.Update(t, matches)
	r.Unlock()
}

// CountUniqSigs counts all the uniq signatures seen in the reduced stats
func (r *Reducer) CountUniqSigs() int {
	uniqSigs := datastructs.NewSyncedSet()
	for comp := range r.m {
		for sig := range r.m[comp].CntBySig {
			uniqSigs.Add(sig)
		}
	}
	return uniqSigs.Len()
}

// Print prints out all the informations stored in the Reducer
func (r *Reducer) Print() {
	cnt := r.CountUniqSigs()
	log.Infof("cnt:%d", cnt)
	//cnt := r.e.Count()
	for computer := range r.m {
		r.m[computer].Finalize(cnt)
		fmt.Println(r.m[computer])
	}
}
