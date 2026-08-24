package parserdiscrepancy

type Outcome string

const (
	Consistent  Outcome = "consistent"
	Split       Outcome = "split"
	Nuke        Outcome = "nuke"
	SplitOrNuke Outcome = "split-or-nuke"
	Polluted    Outcome = "polluted"
	Unstable    Outcome = "unstable"
)

type SignificantHeader struct {
	Label, Name, Value                string
	Body                              []byte
	RemoveContentLength, KeepOriginal bool
}
type Exchange struct {
	Status   int
	Body     []byte
	TimedOut bool
}
type Pair struct {
	Name           string
	Baseline, Test []Exchange
	Expected       Outcome
}
type Result struct {
	Pair             string
	Outcome          Outcome
	Stable, Polluted bool
}

// Classify preserves baseline/test pairing and refuses to report unstable or
// contaminated samples. A timeout or divergent stable status is SplitOrNuke:
// the transport alone cannot safely distinguish a parser split from rejection.
func Classify(p Pair) Result {
	r := Result{Pair: p.Name}
	if len(p.Baseline) < 2 || len(p.Test) < 2 {
		return r
	}
	if !stable(p.Baseline) || !stable(p.Test) {
		r.Outcome = Unstable
		return r
	}
	r.Stable = true
	if contaminated(p.Baseline) || contaminated(p.Test) {
		r.Polluted = true
		r.Outcome = Polluted
		return r
	}
	if p.Test[0].TimedOut || p.Baseline[0].TimedOut != p.Test[0].TimedOut || p.Baseline[0].Status != p.Test[0].Status {
		r.Outcome = SplitOrNuke
	} else {
		r.Outcome = Consistent
	}
	return r
}
func stable(x []Exchange) bool {
	for _, v := range x[1:] {
		if v.Status != x[0].Status || v.TimedOut != x[0].TimedOut {
			return false
		}
	}
	return true
}
func contaminated(x []Exchange) bool {
	for _, v := range x {
		for i := 0; i+8 <= len(v.Body); i++ {
			if string(v.Body[i:i+8]) == "wrtzllsk" {
				return true
			}
		}
	}
	return false
}
