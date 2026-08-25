// Package rawhttp sends caller-owned bytes without net/http canonicalization.
package rawhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Config struct {
	TLS                      bool
	ServerName               string
	Timeout                  time.Duration
	MaxResponseBytes         int64
	MaxRequestsPerConnection int
	Reuse                    bool
	TLSConfig                *tls.Config
}
type Transport struct {
	cfg  Config
	mu   sync.Mutex
	conn net.Conn
	used int
}

func New(c Config) *Transport {
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = 4 << 20
	}
	if c.MaxRequestsPerConnection <= 0 {
		c.MaxRequestsPerConnection = 1
	}
	return &Transport{cfg: c}
}
func (t *Transport) RoundTrip(ctx context.Context, address string, request []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, e := t.connection(ctx, address)
	if e != nil {
		return nil, e
	}
	deadline := time.Now().Add(t.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	if _, e = c.Write(request); e != nil {
		t.poison()
		return nil, e
	}
	r := io.LimitReader(c, t.cfg.MaxResponseBytes+1)
	b, e := io.ReadAll(r)
	if int64(len(b)) > t.cfg.MaxResponseBytes {
		t.poison()
		return nil, fmt.Errorf("response exceeds %d bytes", t.cfg.MaxResponseBytes)
	}
	t.used++
	if e != nil && !isTimeout(e) {
		t.poison()
	}
	if !t.cfg.Reuse || t.used >= t.cfg.MaxRequestsPerConnection {
		t.poison()
	}
	return b, e
}
func (t *Transport) connection(ctx context.Context, a string) (net.Conn, error) {
	if t.conn != nil {
		return t.conn, nil
	}
	d := net.Dialer{Timeout: t.cfg.Timeout}
	c, e := d.DialContext(ctx, "tcp", a)
	if e != nil {
		return nil, e
	}
	if t.cfg.TLS {
		cfg := t.cfg.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: t.cfg.ServerName, MinVersion: tls.VersionTLS12}
		} else {
			cfg = cfg.Clone()
		}
		tc := tls.Client(c, cfg)
		if e = tc.HandshakeContext(ctx); e != nil {
			c.Close()
			return nil, e
		}
		c = tc
	}
	t.conn = c
	t.used = 0
	return c, nil
}
func (t *Transport) poison() {
	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.conn = nil
	t.used = 0
}
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	e := t.conn.Close()
	t.conn = nil
	return e
}
func isTimeout(e error) bool { n, ok := e.(net.Error); return ok && n.Timeout() }
