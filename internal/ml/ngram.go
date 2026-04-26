package ml

import (
	"math"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// NgramVector is a TF feature vector of character n-grams
type NgramVector map[string]float64

// ExtractNgrams extracts 2-grams and 3-grams from a string
func ExtractNgrams(s string) NgramVector {
	s = strings.ToLower(s)
	vec := make(NgramVector)
	runes := []rune(s)
	n := len(runes)

	// 2-grams
	for i := 0; i+1 < n; i++ {
		gram := string(runes[i : i+2])
		vec[gram]++
	}
	// 3-grams
	for i := 0; i+2 < n; i++ {
		gram := string(runes[i : i+3])
		vec[gram]++
	}

	// Normalize to TF
	total := 0.0
	for _, v := range vec {
		total += v
	}
	if total > 0 {
		for k := range vec {
			vec[k] /= total
		}
	}
	return vec
}

// CosineSimilarity computes cosine similarity between two vectors
func CosineSimilarity(a, b NgramVector) float64 {
	dot := 0.0
	normA := 0.0
	normB := 0.0

	for k, va := range a {
		dot += va * b[k]
		normA += va * va
	}
	for _, vb := range b {
		normB += vb * vb
	}

	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// CentroidVector computes the mean vector of a set of vectors
func CentroidVector(vecs []NgramVector) NgramVector {
	if len(vecs) == 0 {
		return NgramVector{}
	}
	centroid := make(NgramVector)
	for _, v := range vecs {
		for k, val := range v {
			centroid[k] += val
		}
	}
	n := float64(len(vecs))
	for k := range centroid {
		centroid[k] /= n
	}
	return centroid
}

// PersonMatch represents the result of matching a filename against a person
type PersonMatch struct {
	PersonName string
	Confidence float64
}

// IdentifyPerson matches filename against known person filenames using n-gram similarity.
// Returns matches sorted by confidence (highest first).
func IdentifyPerson(filename string, personFilenames map[string][]string) []PersonMatch {
	// strip extension for comparison
	base := filenameWithoutExt(filename)
	query := ExtractNgrams(base)

	var results []PersonMatch
	for person, fnames := range personFilenames {
		if len(fnames) == 0 {
			continue
		}
		// build centroid of all known filenames for this person
		vecs := make([]NgramVector, 0, len(fnames))
		for _, fn := range fnames {
			fnBase := filenameWithoutExt(fn)
			vecs = append(vecs, ExtractNgrams(fnBase))
		}
		centroid := CentroidVector(vecs)
		sim := CosineSimilarity(query, centroid)
		results = append(results, PersonMatch{PersonName: person, Confidence: sim})
	}

	// sort descending by confidence
	sortPersonMatches(results)
	return results
}

func filenameWithoutExt(name string) string {
	base := filepath.Base(name)
	ext := filepath.Ext(base)
	if ext != "" {
		base = base[:len(base)-utf8.RuneCountInString(ext)]
	}
	return base
}

func sortPersonMatches(matches []PersonMatch) {
	// simple insertion sort (lists are small)
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j].Confidence > matches[j-1].Confidence; j-- {
			matches[j], matches[j-1] = matches[j-1], matches[j]
		}
	}
}
