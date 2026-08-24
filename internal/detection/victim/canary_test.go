package victim

import "testing"

func TestCanaryAndReflection(t *testing.T) {
	s := Encode(12, 2, 3)
	c, ok := Find([]byte("prefix " + s + " suffix"))
	if !ok || c != (Canary{12, 2, 3}) {
		t.Fatalf("decode: %#v %v", c, ok)
	}
	if !IsReflection(c, 12, 3, 0) || IsReflection(c, 13, 3, 0) || !IsCrossTechnique(c, 13) {
		t.Fatal("reflection ordering")
	}
}
func TestInject(t *testing.T) {
	got := string(Inject([]byte("GET /asdf HTTP/1.1\r\n\r\n"), 1, 2, 3))
	want := "GET /wrtzllsk1x2x3 HTTP/1.1\r\n\r\n"
	if got != want {
		t.Fatalf("%q", got)
	}
}
func TestCorrelation(t *testing.T) {
	r := Correlate(200, 2, [][]int{{500}, {500}, {200}}, [][]int{{200}, {200}, {200}})
	if r.Verdict != Verified {
		t.Fatal(r)
	}
	r = Correlate(200, 2, [][]int{{500}}, [][]int{{503}})
	if r.Verdict != Discard {
		t.Fatal(r)
	}
}
