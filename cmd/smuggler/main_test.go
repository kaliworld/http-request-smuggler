package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PortSwigger/http-request-smuggler/internal/scanner/batch"
)

func TestRunReportsInvalidLinesAsJSONL(t *testing.T) {
	input := strings.NewReader("# comment\nnot-a-url\n")
	var output bytes.Buffer
	if err := run(context.Background(), input, &output, 2, batch.Options{Timeout: time.Millisecond, Techniques: []string{"quoted"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"error":"invalid HTTP(S) URL"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestSplitTechniques(t *testing.T) {
	got := splitTechniques("quoted, CL-plus, ")
	if len(got) != 2 || got[1] != "CL-plus" {
		t.Fatalf("%v", got)
	}
}
