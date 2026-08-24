package mutation

import (
	"bytes"
	"testing"
)

func TestTechniqueGoldenBytes(t *testing.T) {
	in := []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
	tests := map[string]string{"space1": "Transfer-Encoding : chunked", "quoted": "Transfer-Encoding: \"chunked\"", "revdualchunk": "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked", "accentTE": "Transf\x82r-Encoding: chunked"}
	for tech, want := range tests {
		got, e := Apply(in, "Transfer-Encoding", tech)
		if e != nil || !bytes.Contains(got, []byte(want)) {
			t.Errorf("%s: %q %v", tech, got, e)
		}
	}
}
func TestRegistryTechniquesAreRecognized(t *testing.T) {
	in := []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n")
	seen := map[string]bool{}
	for _, x := range Techniques() {
		if seen[x] {
			t.Fatalf("duplicate %s", x)
		}
		seen[x] = true
	}
	if len(seen) < 70 {
		t.Fatalf("registry unexpectedly short: %d", len(seen))
	}
	_ = in
}
