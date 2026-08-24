package report

import "github.com/PortSwigger/http-request-smuggler/internal/protocol"

type Severity string

const (
	Info   Severity = "info"
	Low    Severity = "low"
	Medium Severity = "medium"
	High   Severity = "high"
)

type Finding struct {
	ID, Title, Detail, Background, Remediation string
	Severity                                   Severity
	Confidence                                 string
	Evidence                                   []protocol.Exchange
	Metadata                                   map[string]string
}

func (f Finding) Protocol() protocol.Result {
	return protocol.Result{ID: f.ID, Title: f.Title, Detail: f.Detail, Severity: string(f.Severity), Confidence: f.Confidence, Evidence: f.Evidence, Metadata: f.Metadata}
}
