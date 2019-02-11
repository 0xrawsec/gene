package reducer

import (
	"engine"
	"fmt"
	"sync"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/stats"
)

//////////////////////////// Reducer ////////////////////////////////

// ReducedStats structrur definition
type ReducedStats struct {
	Computer              string
	CntEvents             int
	CntBySig              map[string]int
	UniqSigs              []string
	SumRuleCrit           int
	SumEvtCrit            int
	TotalSigs             int
	AvgEvtsCrit           float64
	AvgSigCrit            float64
	StdDevCrit            float64
	SigDiv                float64
	CntUniqSigs           int
	CntUniqByAvgCritBySig int     `json:"Metric0"`
	AvgEvtCritBySigDiv    float64 `json:"Metric1"`
	sigCrits              []float64
	evtCrits              []float64
	eng                   *engine.Engine
}

// NewReducedStats structure
func NewReducedStats(e *engine.Engine, computer string) *ReducedStats {
	return &ReducedStats{Computer: computer, CntBySig: make(map[string]int), UniqSigs: make([]string, 0), sigCrits: make([]float64, 0), eng: e}
}

// Update ReducedStats with data
func (rs *ReducedStats) Update(matches []string) {
	evtCrit := 0
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
	//rs.SumCriticalities += criticality
	//rs.criticalities = append(rs.criticalities, float64(criticality))
}

// Finalize the computation of the statistics
func (rs *ReducedStats) Finalize() {
	rs.AvgEvtsCrit = stats.Truncate(float64(rs.SumEvtCrit)/float64(rs.CntEvents), 2)

	rs.AvgSigCrit = stats.Truncate(float64(rs.SumRuleCrit)/float64(rs.TotalSigs), 2)
	rs.CntUniqSigs = len(rs.CntBySig)
	rs.CntUniqByAvgCritBySig = rs.CntUniqSigs * int(rs.AvgSigCrit)

	// Compute Standard Dev
	rs.StdDevCrit = stats.Truncate(stats.StdDev(rs.sigCrits), 2)
	rs.SigDiv = float64(rs.CntUniqSigs) * 100 / float64(rs.eng.Count())
	rs.AvgEvtCritBySigDiv = stats.Truncate((rs.AvgEvtsCrit * rs.SigDiv), 2)

	for s := range rs.CntBySig {
		rs.UniqSigs = append(rs.UniqSigs, s)
	}
}

func (rs ReducedStats) String() string {
	rs.Finalize()
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
func (r *Reducer) Update(computer string, matches []string) {
	r.Lock()
	if _, ok := r.m[computer]; !ok {
		r.m[computer] = NewReducedStats(r.e, computer)
	}
	rs := r.m[computer]
	rs.Update(matches)
	r.Unlock()
}

// Print prints out all the informations stored in the Reducer
func (r *Reducer) Print() {
	for computer := range r.m {
		fmt.Println(r.m[computer])
	}
}
