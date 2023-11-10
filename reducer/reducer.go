package reducer

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/stats"
)

func BoundedScoreFormula(score, max int) float64 {
	if max <= 0 {
		return 0
	}
	return stats.Truncate(float64(score)*100.0/float64(max), 1)
}

//////////////////////////// Reducer ////////////////////////////////

// ReducedStats structrure definition
type ReducedStats struct {
	Identifier    string         `json:"identifier"`
	CntAlerts     int            `json:"alert-count"`
	CntBySig      map[string]int `json:"count-by-signature"`
	UniqSigs      []string       `json:"signatures"`
	Techniques    []string       `json:"techniques"`
	Tactics       []string       `json:"tactics"`
	TotalSigs     int            `json:"signature-count"`
	SumAlertSev   int            `json:"sum-alert-severity"`
	AvgAlertSev   float64        `json:"avg-alert-severity"`
	StdDevAlerSev float64        `json:"std-dev-alert-severity"`
	SumRuleSev    int            `json:"sum-rule-severity"`
	AvgSigSev     float64        `json:"avg-signature-severity"`
	StdDevSigSev  float64        `json:"std-dev-signature-severity"`
	SigDiv        float64        `json:"signature-diversity"`
	CntUniqSigs   int            `json:"count-uniq-signatures"`
	// signature severity metric, the higher it is the more attention should be given to the report
	CntUniqByAvgSevBySig int `json:"signature-severity-metric"`
	// alert severity metric, the higher it is the more attention should be given to the report
	AvgAlertSevBySigDiv int `json:"alert-severity-metric"`
	// aggregated metric used to sort statistic reports between them. Higher the score higher the priority
	Score        int       `json:"score"`
	BoundedScore float64   `json:"bounded-score"`
	StartTime    time.Time `json:"start-time"`
	MedianTime   time.Time `json:"median-time"`
	StopTime     time.Time `json:"stop-time"`
	techniques   *datastructs.SyncedSet
	tactics      *datastructs.SyncedSet
	sigCrits     []float64
	alertCrits   []float64
	eng          *engine.Engine
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
	evtSev := 0

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

		if r := rs.eng.GetCompRuleByName(m); r != nil {
			for _, ttp := range r.Attack {
				rs.techniques.Add(ttp.ID)
				rs.tactics.Add(ttp.Tactic)
			}

			// don't take informative rules into account
			if r.Severity != 0 {
				rs.SumRuleSev += r.Severity
				evtSev += r.Severity
				rs.sigCrits = append(rs.sigCrits, float64(r.Severity))
			}
		}

	}
	if evtSev > engine.SeverityBound {
		rs.SumAlertSev += engine.SeverityBound
		rs.alertCrits = append(rs.alertCrits, float64(engine.SeverityBound))
	} else {
		rs.SumAlertSev += evtSev
		rs.alertCrits = append(rs.alertCrits, float64(evtSev))
	}

	rs.CntAlerts++
}

func (rs *ReducedStats) ComputeScore(cntSigs int) int {
	// compute alerts statistics
	rs.AvgAlertSev = stats.Truncate(float64(rs.SumAlertSev)/float64(rs.CntAlerts), 2)
	rs.StdDevAlerSev = stats.Truncate(stats.StdDev(rs.alertCrits), 2)

	// compute signature statistics
	rs.AvgSigSev = stats.Truncate(float64(rs.SumRuleSev)/float64(rs.TotalSigs), 2)
	// Compute Standard Dev
	rs.StdDevSigSev = stats.Truncate(stats.StdDev(rs.sigCrits), 2)
	rs.CntUniqSigs = len(rs.CntBySig)
	rs.CntUniqByAvgSevBySig = rs.CntUniqSigs * int(math.Round(rs.AvgSigSev))

	// The diversity is relative to the number of signatures observed
	// accross the dataset
	rs.SigDiv = stats.Truncate(float64(rs.CntUniqSigs)*100/float64(cntSigs), 2)
	rs.AvgAlertSevBySigDiv = int(math.Round((rs.AvgAlertSev * rs.SigDiv)))

	rs.Score = rs.AvgAlertSevBySigDiv + rs.CntUniqByAvgSevBySig
	return rs.Score
}

// Finalize the computation of the statistics
func (rs *ReducedStats) Finalize(cntSigs, maxScore int) {

	// process techniques
	for _, i := range rs.techniques.Slice() {
		technique := i.(string)
		rs.Techniques = append(rs.Techniques, technique)
	}

	// process tactics
	for _, i := range rs.tactics.Slice() {
		tactic := i.(string)
		rs.Tactics = append(rs.Tactics, tactic)
	}

	// unique signatures
	for s := range rs.CntBySig {
		rs.UniqSigs = append(rs.UniqSigs, s)
	}

	// compute score
	score := rs.ComputeScore(cntSigs)

	rs.BoundedScore = BoundedScoreFormula(score, maxScore)

	rs.MedianTime = rs.StartTime.Add((rs.StopTime.Sub(rs.StartTime)) / 2)
}

func (rs *ReducedStats) String() string {
	var out []byte
	var err error

	if out, err = json.Marshal(rs); err != nil {
		panic(err)
	}

	return string(out)
}

// Reducer structure to store statistics about several machines
type Reducer struct {
	mutex    sync.RWMutex
	e        *engine.Engine
	m        map[string]*ReducedStats
	uniqSigs *datastructs.SyncedSet
	max      int
}

// NewReducer creates a new Reducer structure
func NewReducer(e *engine.Engine) *Reducer {
	return &Reducer{e: e,
		m:        make(map[string]*ReducedStats),
		uniqSigs: datastructs.NewSyncedSet()}
}

func (r *Reducer) Lock() {
	r.mutex.Lock()
	// we mark the max as not computed
	r.max = 0
}

func (r *Reducer) RLock() {
	r.mutex.RLock()
}

func (r *Reducer) Unlock() {
	r.mutex.Unlock()
}

func (r *Reducer) RUnlock() {
	r.mutex.RUnlock()
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
		crs.Finalize(r.CountUniqSigs(), r.MaxScore())
	}
	return
}

// Score is a simpler primitive to return only the score
func (r *Reducer) Score(identifier string) int {
	r.RLock()
	defer r.RUnlock()
	if rs, ok := r.m[identifier]; ok {
		return rs.ComputeScore(r.CountUniqSigs())
	}
	return 0
}

// BoundedScore returns a bounded score in [0; 100] computed relatively
// to the maximum score found in the reducer
func (r *Reducer) BoundedScore(identifier string) float64 {
	r.RLock()
	defer r.RUnlock()
	if rs, ok := r.m[identifier]; ok {
		score := rs.ComputeScore(r.CountUniqSigs())
		max := r.MaxScore()
		return BoundedScoreFormula(score, max)
	}
	return 0
}

// MaxScore returns the maximum score found in the reducer
func (r *Reducer) MaxScore() (max int) {
	r.RLock()
	defer r.RUnlock()

	// don't need to compute the max score
	if r.max != 0 {
		return r.max
	}

	// compute the maximum score
	for _, rs := range r.m {
		score := rs.ComputeScore(r.CountUniqSigs())
		if score > max {
			max = score
		}
	}

	// set max
	r.max = max
	return
}

// Reset ReducedStats according to its identifier
func (r *Reducer) Reset(identifier string) {
	r.Lock()
	defer r.Unlock()
	r.m[identifier] = NewReducedStats(r.e, identifier)
}

// Delete deletes ReducedStats according to its identifier
func (r *Reducer) Delete(identifier string) {
	r.Lock()
	defer r.Unlock()
	delete(r.m, identifier)
}

// CountUniqSigs counts all the uniq signatures seen in the reduced stats
func (r *Reducer) CountUniqSigs() int {
	return r.uniqSigs.Len()
}

// Print prints out all the informations stored in the Reducer
func (r *Reducer) Print() {
	r.RLock()
	defer r.RUnlock()
	for computer := range r.m {
		fmt.Println(r.ReduceCopy(computer))
	}
}
