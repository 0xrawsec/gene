package reducer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/toast"
)

var (
	rules = "test"
)

func TestReducer(t *testing.T) {

	tt := toast.FromT(t)
	identifiers := make([]string, 50)

	e := engine.NewEngine()

	tt.CheckErr(e.LoadDirectory(rules))

	r := NewReducer(e)
	ruleNames := e.GetRuleNames()
	sort.Strings(ruleNames)

	for i := 0; i < len(identifiers); i++ {
		identifier := fmt.Sprintf("machine-%d", i)
		identifiers[i] = identifier
		alertCount := 20

		if rand.Int()%2 == 0 {
			alertCount = 5
		}

		for j := 0; j < alertCount; j++ {
			matches := make([]string, 0)
			for k := 0; k < rand.Int()%5; k++ {
				l := rand.Int() % len(ruleNames)
				matches = append(matches, ruleNames[l])
			}
			r.Update(time.Now(), identifier, matches)
		}
	}

	var worst *ReducedStats
	t.Logf("Maximum score: %d", r.MaxScore())

	for _, id := range identifiers {
		score := r.Score(id)
		bscore := r.BoundedScore(id)
		t.Logf("%s: score=%d bscore=%.1f", id, score, bscore)
		rs := r.ReduceCopy(id)
		if rs.BoundedScore == 100 {
			worst = rs
		}

		tt.Assert(score == rs.Score)
		tt.Assert(bscore == rs.BoundedScore)
	}

	b, err := json.MarshalIndent(worst, "", "  ")
	tt.CheckErr(err)

	// testing print
	r.Print()
	t.Logf(string(b))

	// deleting some identifiers
	for _, id := range identifiers {
		r.Reset(id)
		tt.Assert(r.ReduceCopy(id) != nil)

		r.Delete(id)
		tt.Assert(r.ReduceCopy(id) == nil)
	}
}
