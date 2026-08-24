package victim

import (
	"regexp"
	"strconv"
)

const CanaryPrefix = "wrtzllsk"

type Canary struct{ TechniqueID, Batch, Position int }

var pattern = regexp.MustCompile(CanaryPrefix + `(\d+)x(\d+)x(\d+)`)

func Encode(t, b, p int) string {
	return CanaryPrefix + strconv.Itoa(t) + "x" + strconv.Itoa(b) + "x" + strconv.Itoa(p)
}
func Find(b []byte) (Canary, bool) {
	m := pattern.FindSubmatch(b)
	if m == nil {
		return Canary{}, false
	}
	a, _ := strconv.Atoi(string(m[1]))
	c, _ := strconv.Atoi(string(m[2]))
	d, _ := strconv.Atoi(string(m[3]))
	return Canary{a, c, d}, true
}
func IsReflection(found Canary, t, b, p int) bool {
	return found.TechniqueID == t && (found.Batch < b || (found.Batch == b && found.Position < p))
}
func IsCrossTechnique(found Canary, t int) bool { return found.TechniqueID != t }
func Inject(payload []byte, t, b, p int) []byte {
	out := append([]byte(nil), payload...)
	first := index(out, ' ', 0)
	if first < 0 {
		return out
	}
	second := index(out, ' ', first+1)
	if second < 0 {
		second = index(out, '\r', first+1)
		if second < 0 {
			second = len(out)
		}
	}
	path := string(out[first+1 : second])
	if len(path) == 0 || path[0] != '/' {
		return out
	}
	canary := Encode(t, b, p)
	var np string
	if contains(path, "?") {
		np = path + "&xyz=" + canary
	} else if path == "/" || path == "/favicon.ico" || contains(path, "%") {
		np = path + "?xyz=" + canary
	} else {
		np = "/" + canary
	}
	return append(append(append([]byte{}, out[:first+1]...), []byte(np)...), out[second:]...)
}
func index(b []byte, c byte, start int) int {
	for i := start; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}
func contains(s, x string) bool {
	for i := 0; i+len(x) <= len(s); i++ {
		if s[i:i+len(x)] == x {
			return true
		}
	}
	return false
}

type Verdict string

const (
	Verified     Verdict = "verified"
	Unreplicable Verdict = "unreplicable"
	Discard      Verdict = "discard"
)

type CorrelationResult struct {
	Verdict                      Verdict
	AttackDirtyCycles, CyclesRun int
}

func Correlate(baseline, threshold int, attacks, controls [][]int) CorrelationResult {
	n := len(attacks)
	if len(controls) < n {
		n = len(controls)
	}
	dirty := 0
	for i := 0; i < n; i++ {
		if differs(attacks[i], baseline) {
			dirty++
		}
		if differs(controls[i], baseline) {
			return CorrelationResult{Discard, dirty, i + 1}
		}
	}
	v := Unreplicable
	if dirty >= threshold {
		v = Verified
	}
	return CorrelationResult{v, dirty, n}
}
func differs(xs []int, b int) bool {
	for _, x := range xs {
		if x != b {
			return true
		}
	}
	return false
}
