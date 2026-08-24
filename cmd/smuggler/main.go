// Command smuggler scans authorized HTTP(S) targets from a URL list without
// requiring Burp, smugglerd, or any third-party Go dependency.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PortSwigger/http-request-smuggler/internal/scanner/batch"
)

var version = "dev"

func main() {
	input := flag.String("input", "url.txt", "URL list file, or - for stdin")
	output := flag.String("output", "-", "JSON Lines output file, or - for stdout")
	concurrency := flag.Int("concurrency", 4, "maximum concurrent targets")
	timeout := flag.Duration("timeout", 10*time.Second, "timeout per probe")
	techniquesFlag := flag.String("techniques", strings.Join(batch.DefaultTechniques, ","), "comma-separated mutation techniques")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *concurrency < 1 || *concurrency > 64 {
		fatal("concurrency must be between 1 and 64")
	}
	techniques := splitTechniques(*techniquesFlag)
	if err := batch.ValidateTechniques(techniques); err != nil {
		fatal(err.Error())
	}
	in, closeIn, err := openInput(*input)
	if err != nil {
		fatal(err.Error())
	}
	defer closeIn()
	out, closeOut, err := openOutput(*output)
	if err != nil {
		fatal(err.Error())
	}
	defer closeOut()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, in, out, *concurrency, batch.Options{Timeout: *timeout, Techniques: techniques}); err != nil {
		fatal(err.Error())
	}
}

func run(ctx context.Context, input io.Reader, output io.Writer, concurrency int, options batch.Options) error {
	urls := make(chan string)
	results := make(chan batch.Result)
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range urls {
				results <- batch.Scan(ctx, target, options)
			}
		}()
	}
	go func() { workers.Wait(); close(results) }()
	scanErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text())
			if target == "" || strings.HasPrefix(target, "#") {
				continue
			}
			select {
			case urls <- target:
			case <-ctx.Done():
				close(urls)
				scanErr <- ctx.Err()
				return
			}
		}
		close(urls)
		scanErr <- scanner.Err()
	}()
	encoder := json.NewEncoder(output)
	for result := range results {
		if err := encoder.Encode(result); err != nil {
			return err
		}
	}
	return <-scanErr
}

func splitTechniques(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
func openInput(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, e := os.Open(path)
	return f, func() {
		if f != nil {
			_ = f.Close()
		}
	}, e
}
func openOutput(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, e := os.Create(path)
	return f, func() {
		if f != nil {
			_ = f.Close()
		}
	}, e
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "smuggler:", message); os.Exit(2) }
