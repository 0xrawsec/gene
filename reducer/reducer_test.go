package reducer

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
)

var (
	rules = "test"
)

func TestReducer(t *testing.T) {
	rand.Seed(158)
	identifiers := make([]string, 50)

	e := engine.NewEngine()
	if err := e.LoadDirectory(rules); err != nil {
		t.Errorf("Failed to load engine: %s", err)
		t.FailNow()
	}

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
	t.Logf("Maximum score: %d", r.MaxScore())

	for _, id := range identifiers {
		score := r.Score(id)
		bscore := r.BoundedScore(id)
		t.Logf("%s: score=%d bscore=%.1f", id, score, bscore)
		rs := r.ReduceCopy(id)
		if rs.BoundedScore == 100 {
			worst = rs
		}
		if score != rs.Score {
			t.Errorf("Scores are not equal")
		}
		if bscore != rs.BoundedScore {
			t.Errorf("Bounded scores are not equal")
		}
	}

	b, _ := json.MarshalIndent(worst, "", "  ")
	t.Logf(string(b))
}
