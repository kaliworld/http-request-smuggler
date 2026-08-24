package rawhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestRoundTripPreservesMalformedRequest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	want := []byte("POST / HTTP/1.1\r\nX-Dupe: one\r\nX-Dupe: two\r\nBad :\x00value\r\nContent-Length: 0\r\n\r\n")
	received := make(chan []byte, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(want))
		_, _ = io.ReadFull(conn, buf)
		received <- buf
		_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	}()
	transport := New(Config{Timeout: time.Second, MaxResponseBytes: 1024})
	defer transport.Close()
	response, err := transport.RoundTrip(context.Background(), listener.Addr().String(), want)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-received; !bytes.Equal(got, want) {
		t.Fatalf("wire bytes changed\nwant %q\n got %q", want, got)
	}
	if !bytes.HasPrefix(response, []byte("HTTP/1.1 204")) {
		t.Fatalf("unexpected response: %q", response)
	}
}
