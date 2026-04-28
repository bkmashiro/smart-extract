package ml

import (
	"math"
	"math/rand"

	"github.com/bkmashiro/smart-extract/internal/config"
)

// RankedPassword pairs a password with its sampled Thompson score
type RankedPassword struct {
	Password string
	Score    float64
}

// RankPasswordsThompson ranks passwords for a person using Thompson Sampling.
// Passwords with proven track records (alpha > 1, beta == 1, i.e. only successes)
// are placed first deterministically (sorted by alpha descending).
// Remaining passwords are ranked by sampling from Beta(alpha, beta).
func RankPasswordsThompson(personName string, passwords []string, learned *config.Learned) []RankedPassword {
	var proven []RankedPassword
	var uncertain []RankedPassword

	for _, pw := range passwords {
		stats := config.GetOrCreateStats(learned, personName, pw)
		if stats.Alpha > 1 && stats.Beta == 1 {
			// This password has only successes — deterministically first
			proven = append(proven, RankedPassword{Password: pw, Score: stats.Alpha})
		} else {
			score := sampleBeta(stats.Alpha, stats.Beta)
			uncertain = append(uncertain, RankedPassword{Password: pw, Score: score})
		}
	}

	// Sort proven passwords by alpha descending (most successful first)
	for i := 1; i < len(proven); i++ {
		for j := i; j > 0 && proven[j].Score > proven[j-1].Score; j-- {
			proven[j], proven[j-1] = proven[j-1], proven[j]
		}
	}

	// Sort uncertain passwords by Thompson sample descending
	for i := 1; i < len(uncertain); i++ {
		for j := i; j > 0 && uncertain[j].Score > uncertain[j-1].Score; j-- {
			uncertain[j], uncertain[j-1] = uncertain[j-1], uncertain[j]
		}
	}

	return append(proven, uncertain...)
}

// sampleBeta samples from Beta(alpha, beta) distribution.
// Uses the Johnk method: if X ~ Gamma(alpha,1) and Y ~ Gamma(beta,1),
// then X/(X+Y) ~ Beta(alpha,beta).
func sampleBeta(alpha, beta float64) float64 {
	x := sampleGamma(alpha)
	y := sampleGamma(beta)
	if x+y == 0 {
		return 0.5
	}
	return x / (x + y)
}

// sampleGamma samples from Gamma(shape, 1) using Marsaglia-Tsang's method.
func sampleGamma(shape float64) float64 {
	if shape < 1 {
		// Boost trick: Gamma(shape) = Gamma(shape+1) * U^(1/shape)
		u := rand.Float64()
		if u == 0 {
			u = 1e-10
		}
		return sampleGamma(shape+1) * math.Pow(u, 1.0/shape)
	}

	d := shape - 1.0/3.0
	c := 1.0 / (3.0 * math.Sqrt(d))

	for {
		x := rand.NormFloat64()
		v := 1.0 + c*x
		if v <= 0 {
			continue
		}
		v = v * v * v
		u := rand.Float64()
		if u == 0 {
			u = 1e-10
		}
		x2 := x * x
		if u < 1.0-0.0331*(x2*x2) {
			return d * v
		}
		if math.Log(u) < 0.5*x2+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}

// CheckClusteringHint checks recent unknowns to see if multiple files share the same password.
// Returns a hint string if clustering is suggested, or empty string if not.
func CheckClusteringHint(password string, learned *config.Learned) string {
	// Count how many files in exact cache use this password
	count := 0
	for _, pw := range learned.Exact {
		if pw == password {
			count++
		}
	}
	if count >= 2 {
		return "提示：多个未知文件使用了相同密码，考虑为其创建一个人物档案。"
	}
	return ""
}
