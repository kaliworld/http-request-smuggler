package parserdiscrepancy

import "testing"

func TestClassify(t *testing.T) {
	p := Pair{Name: "hidden", Baseline: []Exchange{{Status: 200}, {Status: 200}}, Test: []Exchange{{Status: 400}, {Status: 400}}}
	if got := Classify(p); got.Outcome != SplitOrNuke || !got.Stable {
		t.Fatal(got)
	}
	p.Test[1].Status = 500
	if got := Classify(p); got.Outcome != Unstable {
		t.Fatal(got)
	}
}
