package secretscan

import "math"

const (
	// EntropyThresholdBase64 is the minimum Shannon entropy for base64-like secrets.
	EntropyThresholdBase64 = 3.5
	// EntropyThresholdHex is the minimum Shannon entropy for hex-encoded secrets.
	EntropyThresholdHex = 3.0
)

// ShannonEntropy calculates the Shannon entropy of a string.
// Returns a value in [0, log2(|alphabet|)]; higher means more random.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsHighEntropy returns true when the string's entropy exceeds the given threshold.
func IsHighEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) >= threshold
}

// IsBase64Charset returns true when all characters belong to the base64 alphabet.
func IsBase64Charset(s string) bool {
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// IsHexCharset returns true when all characters are hexadecimal digits.
func IsHexCharset(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
