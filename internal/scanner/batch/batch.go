// Package batch implements the standalone command's URL-oriented scan runner.
// It only uses the standard library and sends probes through the byte-exact
// rawhttp transport.
package batch

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PortSwigger/http-request-smuggler/internal/mutation"
	"github.com/PortSwigger/http-request-smuggler/internal/scanner/rawhttp"
)

var DefaultTechniques = []string{"space1", "nospace1", "quoted", "revdualchunk", "CL-plus", "CL-dualCL"}

type Options struct {
	Timeout    time.Duration
	Techniques []string
}

type Probe struct {
	Technique string `json:"technique"`
	Status    int    `json:"status,omitempty"`
	Duration  int64  `json:"duration_ms"`
	Error     string `json:"error,omitempty"`
	Different bool   `json:"different_from_baseline"`
}

type Result struct {
	URL            string  `json:"url"`
	BaselineStatus int     `json:"baseline_status,omitempty"`
	PotentialIssue bool    `json:"potential_issue"`
	Error          string  `json:"error,omitempty"`
	Probes         []Probe `json:"probes,omitempty"`
}

func Scan(ctx context.Context, rawURL string, options Options) Result {
	result := Result{URL: rawURL}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		result.Error = "invalid HTTP(S) URL"
		return result
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	if len(options.Techniques) == 0 {
		options.Techniques = DefaultTechniques
	}
	request := requestFor(u)
	baseline := send(ctx, u, request, options.Timeout, "baseline")
	result.BaselineStatus = baseline.Status
	result.Probes = append(result.Probes, baseline)
	if baseline.Error != "" {
		result.Error = "baseline failed: " + baseline.Error
		return result
	}
	for _, technique := range options.Techniques {
		header := "Transfer-Encoding"
		if strings.HasPrefix(technique, "CL-") {
			header = "Content-Length"
		}
		mutated, mutationErr := mutation.Apply(request, header, technique)
		if mutationErr != nil {
			result.Probes = append(result.Probes, Probe{Technique: technique, Error: mutationErr.Error()})
			continue
		}
		probe := send(ctx, u, mutated, options.Timeout, technique)
		probe.Different = probe.Error != "" || probe.Status != result.BaselineStatus
		result.PotentialIssue = result.PotentialIssue || probe.Different
		result.Probes = append(result.Probes, probe)
	}
	return result
}

func requestFor(u *url.URL) []byte {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	host := u.Host
	return []byte("POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: smuggler/1\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")
}

func send(ctx context.Context, u *url.URL, request []byte, timeout time.Duration, technique string) Probe {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	t := rawhttp.New(rawhttp.Config{TLS: u.Scheme == "https", ServerName: u.Hostname(), Timeout: timeout, MaxResponseBytes: 1 << 20})
	defer t.Close()
	started := time.Now()
	response, err := t.RoundTrip(ctx, net.JoinHostPort(u.Hostname(), port), request)
	p := Probe{Technique: technique, Duration: time.Since(started).Milliseconds(), Status: statusCode(response)}
	if err != nil {
		p.Error = err.Error()
	}
	return p
}

func statusCode(response []byte) int {
	line, _ := bufio.NewReader(strings.NewReader(string(response))).ReadString('\n')
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	status, _ := strconv.Atoi(fields[1])
	return status
}

func ValidateTechniques(techniques []string) error {
	known := make(map[string]bool)
	for _, technique := range mutation.Techniques() {
		known[technique] = true
	}
	for _, technique := range techniques {
		if !known[technique] {
			return fmt.Errorf("unknown technique %q", technique)
		}
	}
	return nil
}
