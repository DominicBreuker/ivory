package brainpool

import (
	"crypto/rand"
	"math"
	"os"
	"testing"
	"time"
)

// TestTimingLeaks is a dudect-style check (Reparaz, Balasch, Verbauwhede,
// "Dude, is my code constant time?", 2017): it times the scalar
// multiplication for two classes of secret scalars, interleaved in random
// order, and computes Welch's t statistic. |t| > 4.5 suggests that the
// time depends on the class. Class 0 is a fixed scalar with a single bit
// set (the most "unbalanced" input), class 1 random scalars. The base
// point is fixed.
//
// It is slow and sensitive to machine noise, so it runs only with
// IVORY_TIMING=1. A pass is evidence, not proof; the constant-time review
// in docs/ is the primary argument.
func TestTimingLeaks(t *testing.T) {
	if os.Getenv("IVORY_TIMING") != "1" {
		t.Skip("set IVORY_TIMING=1 to run")
	}
	const samples = 3000
	for _, c := range allCurves {
		t.Run(c.name, func(t *testing.T) {
			fixed := make([]byte, c.size)
			fixed[c.size-1] = 1
			var n [2]float64
			var mean, m2 [2]float64
			class := make([]byte, samples)
			if _, err := rand.Read(class); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < samples; i++ {
				cl := int(class[i] & 1)
				k := fixed
				if cl == 1 {
					k = make([]byte, c.size)
					rand.Read(k)
				}
				start := time.Now()
				c.scalarMult(c.g, k)
				d := float64(time.Since(start).Nanoseconds())
				// Welford's online mean and variance.
				n[cl]++
				delta := d - mean[cl]
				mean[cl] += delta / n[cl]
				m2[cl] += delta * (d - mean[cl])
			}
			v0, v1 := m2[0]/(n[0]-1), m2[1]/(n[1]-1)
			tStat := (mean[0] - mean[1]) / math.Sqrt(v0/n[0]+v1/n[1])
			t.Logf("n = %v/%v, mean %.0f/%.0f ns, sd %.0f/%.0f ns, t = %.2f",
				n[0], n[1], mean[0], mean[1], math.Sqrt(v0), math.Sqrt(v1), tStat)
			if math.Abs(tStat) > 4.5 {
				t.Errorf("|t| = %.2f > 4.5: timing may depend on the scalar", math.Abs(tStat))
			}
		})
	}
}
