package reducer

import (
	"fmt"
	"sync"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/stats"
)

//////////////////////////// Reducer ////////////////////////////////

// ReducedStats structrur definition
type ReducedStats struct {
	Computer                  string
	CountBySig                map[string]int
	UniqueSigs                []string
	SumCriticalities          int
	TotalSigs                 int
	AverageCriticality        float64
	StdDevCriticality         float64
	CountUniqueSigs           int
	CntUniqueByAvgCriticality int     `json:"Metric0"`
	AvgCritPlusStdDev         float64 `json:"Metric1"`
	criticalities             []float64
}

// NewReducedStats structure
func NewReducedStats(computer string) *ReducedStats {
	return &ReducedStats{Computer: computer, CountBySig: make(map[string]int), UniqueSigs: make([]string, 0), criticalities: make([]float64, 0)}
}

// Update ReducedStats with data
func (rs *ReducedStats) Update(criticality int, matches []string) {
	for _, m := range matches {
		rs.CountBySig[m]++
		rs.TotalSigs++
	}
	rs.SumCriticalities += criticality
	rs.criticalities = append(rs.criticalities, float64(criticality))
}

// Finalize the computation of the statistics
func (rs *ReducedStats) Finalize() {
	rs.AverageCriticality = stats.Truncate(float64(rs.SumCriticalities)/float64(rs.TotalSigs), 2)
	rs.CountUniqueSigs = len(rs.CountBySig)
	rs.CntUniqueByAvgCriticality = rs.CountUniqueSigs * int(rs.AverageCriticality)

	// Compute Standard Dev
	rs.StdDevCriticality = stats.Truncate(stats.StdDev(rs.criticalities), 2)

	rs.AvgCritPlusStdDev = stats.Truncate(rs.AverageCriticality+rs.StdDevCriticality, 2)

	for s := range rs.CountBySig {
		rs.UniqueSigs = append(rs.UniqueSigs, s)
	}
}

func (rs ReducedStats) String() string {
	rs.Finalize()
	return string(evtx.ToJSON(rs))
}

// Reducer structure to store statistics about several machines
type Reducer struct {
	sync.RWMutex
	m map[string]*ReducedStats
}

// NewReducer creates a new Reducer structure
func NewReducer() *Reducer {
	return &Reducer{m: make(map[string]*ReducedStats)}
}

// Update a ReducedStats stored in Reducer with data
func (r *Reducer) Update(computer string, criticality int, matches []string) {
	r.Lock()
	if _, ok := r.m[computer]; !ok {
		r.m[computer] = NewReducedStats(computer)
	}
	rs := r.m[computer]
	rs.Update(criticality, matches)
	r.Unlock()
}

// Print prints out all the informations stored in the Reducer
func (r *Reducer) Print() {
	for computer := range r.m {
		fmt.Println(r.m[computer])
	}
}
