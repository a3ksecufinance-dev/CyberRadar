package main

import (
	"fmt"
	"sort"
	"time"
)

// A distribution, reported as the percentiles a DSI asks for rather than as an
// average. An average latency hides the tail, and the tail is what a user
// feels: the platform's own target is expressed as a p95 for that reason.

type sample struct {
	values []time.Duration
}

func (s *sample) add(d time.Duration) { s.values = append(s.values, d) }

func (s *sample) n() int { return len(s.values) }

// quantile uses nearest-rank, which needs no interpolation and cannot invent a
// value the run never saw. With a thousand samples the difference from a
// linear interpolation is below the measurement's own noise.
func (s *sample) quantile(q float64) time.Duration {
	if len(s.values) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(s.values))
	copy(sorted, s.values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(q*float64(len(sorted))+0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func (s *sample) max() time.Duration {
	var out time.Duration
	for _, v := range s.values {
		if v > out {
			out = v
		}
	}
	return out
}

func (s *sample) summary() string {
	if s.n() == 0 {
		return "aucun échantillon"
	}
	return fmt.Sprintf("p50 %s · p95 %s · p99 %s · max %s  (%d échantillons)",
		ms(s.quantile(0.50)), ms(s.quantile(0.95)), ms(s.quantile(0.99)), ms(s.max()), s.n())
}

func ms(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.0f ms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

// median of a set of rates. Separate from sample, which holds durations and
// reports tail quantiles; a drain rate wants its middle, not its tail.
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[len(s)/2]
}
