// Package protocol defines the versioned, Burp-independent IPC contract.
package protocol

import (
	"encoding/base64"
	"errors"
	"time"
)

const Version = "v1"
const MaxMessageBytes int64 = 4 << 20

type Target struct {
	Scheme, Host string
	Port         int
}
type Config struct {
	Scanner                  string
	Technique                string
	TimeoutMillis            int
	MaxRequestsPerConnection int
	ReuseConnections         bool
}
type Exchange struct {
	Request, Response Bytes
	Error             string
	DurationMillis    int64
}
type ScanRequest struct {
	Version    string
	Operation  string
	Target     Target
	RawRequest Bytes
	Config     Config
}
type ScanResponse struct {
	Version string
	Results []Result
	Error   string
}
type Result struct {
	ID, Title, Detail, Severity, Confidence string
	Evidence                                []Exchange
	Metadata                                map[string]string
}

type Bytes []byte

func (b Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + base64.StdEncoding.EncodeToString(b) + `"`), nil
}
func (b *Bytes) UnmarshalJSON(v []byte) error {
	if len(v) < 2 {
		return errors.New("invalid byte string")
	}
	x, e := base64.StdEncoding.DecodeString(string(v[1 : len(v)-1]))
	*b = x
	return e
}
func (r ScanRequest) Validate() error {
	if r.Version != Version {
		return errors.New("unsupported protocol version")
	}
	if r.Operation != "scan" && r.Operation != "mutate" {
		return errors.New("operation not allowed")
	}
	if r.Target.Host == "" || r.Target.Port < 1 || r.Target.Port > 65535 {
		return errors.New("invalid target")
	}
	if len(r.RawRequest) == 0 {
		return errors.New("empty request")
	}
	return nil
}
func (c Config) Timeout() time.Duration {
	if c.TimeoutMillis <= 0 {
		return 10 * time.Second
	}
	if c.TimeoutMillis > 60000 {
		return 60 * time.Second
	}
	return time.Duration(c.TimeoutMillis) * time.Millisecond
}
