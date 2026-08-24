package batch

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestScanUsesLocalRawServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			reader := bufio.NewReader(conn)
			for {
				line, _ := reader.ReadString('\n')
				if line == "\r\n" {
					break
				}
			}
			// Consume the fixed five-byte chunk terminator used by requestFor.
			body := make([]byte, 5)
			_, _ = io.ReadFull(reader, body)
			_, _ = fmt.Fprint(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			_ = conn.Close()
		}
	}()
	result := Scan(context.Background(), "http://"+listener.Addr().String()+"/test", Options{Timeout: time.Second, Techniques: []string{"quoted"}})
	if result.Error != "" || result.PotentialIssue || len(result.Probes) != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	<-done
}

func TestRejectsUnsupportedURL(t *testing.T) {
	result := Scan(context.Background(), "file:///etc/passwd", Options{})
	if result.Error == "" {
		t.Fatal("expected validation error")
	}
}
