package main

import (
	"testing"
	"time"
)

// The ladder's verdict decides what figure gets published, and on a healthy
// platform none of its failure paths is ever taken — the three measurement
// runs that produced the first figures saw every rung hold. A branch that
// never runs is a branch nobody has checked, so the classification is pinned
// here rather than trusted.
func TestARungIsHeldOnlyWhenNothingWasLost(t *testing.T) {
	for _, c := range []struct {
		name string
		r    rung
		want bool
		says string
	}{
		{
			name: "tout est passé et le pipeline a suivi",
			r:    rung{Sent: 5000, Accepted: 5000, Published: 5000, Drained: 5000},
			want: true,
		},
		{
			name: "le collecteur en a refusé",
			r:    rung{Sent: 5000, Accepted: 5000, Published: 4990, Failed: 10, Drained: 5000},
			want: false, says: "refusés",
		},
		{
			name: "accepté mais publié nulle part",
			r:    rung{Sent: 5000, Accepted: 5000, Published: 4000, Drained: 4000},
			want: false, says: "publiés",
		},
		{
			name: "la file de rebut a grossi",
			r:    rung{Sent: 5000, Accepted: 5000, Published: 5000, Drained: 5000, DLQGrowth: 3},
			want: false, says: "rebut",
		},
		{
			name: "le pipeline a pris du retard",
			r:    rung{Sent: 5000, Accepted: 5000, Published: 5000, Drained: 3100},
			want: false, says: "pipeline",
		},
	} {
		got := classify(&c.r, 15*time.Second)
		if got != c.want {
			t.Errorf("%s : tenu=%v, attendu %v (note %q)", c.name, got, c.want, c.r.Note)
		}
		if !c.want && c.says != "" && !contains(c.r.Note, c.says) {
			t.Errorf("%s : la note ne dit pas pourquoi — %q ne contient pas %q",
				c.name, c.r.Note, c.says)
		}
	}
}

// A ladder whose rungs keep going faster has not found the ceiling; one whose
// offered rate doubles for a tenth more throughput has.
func TestSaturationIsDistinguishedFromRunningOutOfRungs(t *testing.T) {
	climbing := []rung{
		{Offered: 1000, Achieved: 950, OK: true},
		{Offered: 2000, Achieved: 1900, OK: true},
	}
	if saturated(climbing) {
		t.Error("une échelle qui monte encore est déclarée saturée")
	}

	plateau := []rung{
		{Offered: 8000, Achieved: 5062, OK: true},
		{Offered: 16000, Achieved: 5716, OK: true},
	}
	if !saturated(plateau) {
		t.Error("un débit qui plafonne quand l'offre double n'est pas reconnu comme saturé")
	}

	// One rung cannot show a trend, whatever it reads.
	if saturated([]rung{{Offered: 16000, Achieved: 5716, OK: true}}) {
		t.Error("un seul palier suffit à déclarer une saturation")
	}

	// A ladder that broke has not saturated — it failed, which is a different
	// sentence and a different number.
	broke := []rung{
		{Offered: 8000, Achieved: 5062, OK: true},
		{Offered: 16000, Achieved: 5716, OK: false},
	}
	if saturated(broke) {
		t.Error("un palier qui a cédé est compté comme une saturation")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
