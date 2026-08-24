package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/PortSwigger/http-request-smuggler/internal/protocol"
	"github.com/PortSwigger/http-request-smuggler/internal/scanner"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	network := flag.String("network", "unix", "unix or tcp")
	address := flag.String("address", "", "socket path or loopback address")
	token := flag.String("token", "", "required bearer token")
	maxConcurrent := flag.Int("max-concurrent", 4, "maximum concurrent scans")
	flag.Parse()
	if *token == "" {
		log.Fatal("-token is required")
	}
	if *address == "" {
		if *network == "unix" {
			*address = filepath.Join(os.TempDir(), fmt.Sprintf("smugglerd-%d.sock", os.Getpid()))
		} else {
			*address = "127.0.0.1:0"
		}
	}
	if *network != "unix" && *network != "tcp" {
		log.Fatal("network must be unix or tcp")
	}
	if *network == "tcp" {
		host, _, e := net.SplitHostPort(*address)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			log.Fatal("TCP listener must use a numeric loopback address")
		}
	}
	if *network == "unix" {
		_ = os.Remove(*address)
	}
	ln, e := net.Listen(*network, *address)
	if e != nil {
		log.Fatal(e)
	}
	if *network == "unix" {
		_ = os.Chmod(*address, 0600)
		defer os.Remove(*address)
	}
	log.Printf("LISTEN %s", ln.Addr())
	sem := make(chan struct{}, *maxConcurrent)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"version": protocol.Version})
	})
	mux.HandleFunc("/v1/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		want := "Bearer " + *token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, protocol.MaxMessageBytes)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req protocol.ScanRequest
		if e := dec.Decode(&req); e != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		if e := req.Validate(); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), req.Config.Timeout())
		defer cancel()
		res, e := scanner.Run(ctx, req)
		if e != nil {
			http.Error(w, e.Error(), 422)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 65 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		ctx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		srv.Shutdown(ctx)
	}()
	if e = srv.Serve(ln); e != nil && e != http.ErrServerClosed {
		log.Fatal(e)
	}
}
