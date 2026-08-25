package scanner

import (
	"context"
	"fmt"
	"github.com/PortSwigger/http-request-smuggler/internal/mutation"
	"github.com/PortSwigger/http-request-smuggler/internal/protocol"
	"github.com/PortSwigger/http-request-smuggler/internal/scanner/rawhttp"
	"net"
	"strconv"
)

func Run(ctx context.Context, r protocol.ScanRequest) (protocol.ScanResponse, error) {
	raw := []byte(r.RawRequest)
	if r.Config.Technique != "" {
		var e error
		raw, e = mutation.Apply(raw, "Transfer-Encoding", r.Config.Technique)
		if e != nil {
			return protocol.ScanResponse{}, e
		}
	}
	if r.Operation == "mutate" {
		return protocol.ScanResponse{Version: protocol.Version, Results: []protocol.Result{{ID: "mutation", Title: "Byte-exact mutation", Evidence: []protocol.Exchange{{Request: raw}}}}}, nil
	}
	cfg := rawhttp.Config{TLS: r.Target.Scheme == "https", ServerName: r.Target.Host, Timeout: r.Config.Timeout(), Reuse: r.Config.ReuseConnections, MaxRequestsPerConnection: r.Config.MaxRequestsPerConnection}
	t := rawhttp.New(cfg)
	defer t.Close()
	resp, e := t.RoundTrip(ctx, net.JoinHostPort(r.Target.Host, strconv.Itoa(r.Target.Port)), raw)
	ex := protocol.Exchange{Request: raw, Response: resp}
	if e != nil {
		ex.Error = e.Error()
	}
	return protocol.ScanResponse{Version: protocol.Version, Results: []protocol.Result{{ID: "raw-probe", Title: fmt.Sprintf("Raw probe: %s", r.Config.Scanner), Severity: "info", Confidence: "tentative", Evidence: []protocol.Exchange{ex}}}}, nil
}
