//go:build integration

// Integration test for goroutine/memory leaks in atprp-ssh-relay.
//
// Starts the real server with TEST_ACCEPT_ANY_KEY=1 (bypasses ATProto
// identity, accepts any key). Creates persistent SSH sessions across
// waves of churn — open, keep alive, close — while monitoring
// goroutine count and heap via the server's pprof endpoint.
//
// Run:
//   cd atproto-reverse-proxy/src/golang
//   go test -vet=off -tags=integration -run TestSSHRelayLeak -count=1 -timeout 180s -v ./cmd/atprp-ssh-relay/

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// Subprocess management
// ---------------------------------------------------------------------------

func moduleRoot(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "env", "GOMOD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	modPath := string(bytes.TrimSpace(out))
	if modPath == "" || modPath == os.DevNull {
		t.Fatal("GOMOD is empty — run from within the Go module")
	}
	return filepath.Dir(modPath)
}

func startServer(t *testing.T) (sshAddr, pprofAddr string, kill func()) {
	t.Helper()

	root := moduleRoot(t)
	tmpBin, err := os.CreateTemp("", "atprp-ssh-relay-*")
	if err != nil {
		t.Fatalf("create temp binary: %v", err)
	}
	tmpBin.Close()
	bin := tmpBin.Name()

	build := exec.Command("go", "build", "-o", bin, "./cmd/atprp-ssh-relay/")
	build.Dir = root
	build.Stderr = os.Stderr
	if out, err := build.Output(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"SSH_LISTEN_ADDR=127.0.0.1:0",
		"PPROF_LISTEN_ADDR=127.0.0.1:0",
		"TEST_ACCEPT_ANY_KEY=1",
		"CADDY_SOCK=",
	)

	stderr, _ := cmd.StderrPipe()
	cmd.Stdout = os.Stdout

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	kill = func() {
		cmd.Process.Signal(os.Interrupt)
		cmd.Wait()
	}

	// Read addresses from stderr. Don't start a background scanner until
	// we've found both — bufio.Scanner is not goroutine-safe.
	scanner := bufio.NewScanner(stderr)
	var sshOK, pprofOK bool
	for scanner.Scan() {
		line := scanner.Text()
		if !sshOK && strings.Contains(line, "SSH listening on ") {
			sshAddr = line[strings.Index(line, "SSH listening on ")+len("SSH listening on "):]
			sshOK = true
		}
		if !pprofOK && strings.Contains(line, "pprof listening on ") {
			pprofAddr = line[strings.Index(line, "pprof listening on ")+len("pprof listening on "):]
			pprofOK = true
		}
		if sshOK && pprofOK {
			break
		}
	}
	// Drain remaining stderr in background so the pipe doesn't fill up.
	go func() {
		for scanner.Scan() {
		}
	}()
	if !sshOK || !pprofOK {
		kill()
		t.Fatalf("server startup timeout: ssh=%v pprof=%v", sshOK, pprofOK)
	}

	pprofCtx, pprofCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pprofCancel()
	if err := waitForPprof(pprofCtx, pprofAddr); err != nil {
		kill()
		t.Fatalf("pprof not ready: %v", err)
	}

	t.Logf("server: ssh=%s pprof=%s", sshAddr, pprofAddr)
	return sshAddr, pprofAddr, kill
}

func waitForPprof(ctx context.Context, addr string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			resp, err := http.Get("http://" + addr + "/debug/pprof/")
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				return nil
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SSH session pool
// ---------------------------------------------------------------------------

type sshSession struct {
	client *ssh.Client
}

func newSigner() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	return s
}

func dialSession(t *testing.T, addr string, id int) *sshSession {
	// Dial TCP with a deadline so the SSH handshake can't hang forever.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	config := &ssh.ClientConfig{
		User: fmt.Sprintf("user-%d", id),
		Auth: []ssh.AuthMethod{ssh.PublicKeys(newSigner())},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 5 * time.Second,
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil
	}
	return &sshSession{client: ssh.NewClient(c, chans, reqs)}
}

func (s *sshSession) close() {
	// ssh.Client.Close() calls mux.Wait() which can block for a long
	// time. Close in the background — the TCP RST still tears down the
	// server-side connection immediately.
	if s.client != nil {
		go s.client.Close()
	}
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

type serverStats struct {
	goroutines int
	heapBytes  int64
}

func collectStats(ctx context.Context, pprofAddr string) (serverStats, error) {
	g, err := goroutineCount(ctx, pprofAddr)
	if err != nil {
		return serverStats{}, err
	}
	h, err := heapInUseBytes(ctx, pprofAddr)
	if err != nil {
		return serverStats{}, err
	}
	return serverStats{g, h}, nil
}

func goroutineCount(ctx context.Context, pprofAddr string) (int, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://"+pprofAddr+"/debug/pprof/goroutine?debug=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var total int
	fmt.Sscanf(string(body), "goroutine profile: total %d", &total)
	return total, nil
}

func heapInUseBytes(ctx context.Context, pprofAddr string) (int64, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET",
		"http://"+pprofAddr+"/debug/pprof/heap?debug=1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var inuse, bytes int64
	fmt.Sscanf(string(body), "heap profile: %d: %d", &inuse, &bytes)
	return bytes, nil
}

func fmtBytes(b int64) string {
	switch {
	case b >= 10*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 10*1024:
		return fmt.Sprintf("%.0f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// ---------------------------------------------------------------------------
// Test — opens and closes SSH sessions in waves, measuring the server
// after each wave to verify goroutines and heap don't grow unboundedly.
// ---------------------------------------------------------------------------

func TestSSHRelayLeak(t *testing.T) {
	sshAddr, pprofAddr, kill := startServer(t)
	defer kill()

	ctx := context.Background()

	base, err := collectStats(ctx, pprofAddr)
	if err != nil {
		t.Fatalf("baseline stats: %v", err)
	}

	// Concurrency cap: limit how many dials are in-flight at once.
	// Without this, ssh.Dial goroutines from timed-out waves pile up
	// and contaminate subsequent measurements.
	sem := make(chan struct{}, 10)

	type step struct {
		name  string
		open  int
		close int
	}
	waves := []step{
		{"▲ 50", 50, 0},   //   0 →  50 live
		{"▲ 100", 50, 0},  //  50 → 100 live
		{"▲ 150", 50, 0},  // 100 → 150 live
		{"▲ 200", 50, 0},  // 150 → 200 live — maxConnsLimit
		{"▼ 100", 0, 100}, // 200 → 100 live
		{"▼ 50", 0, 50},   // 100 →  50 live
		{"▼ 0", 0, 50},    //  50 →   0 live — all closed
		{"▲ 200", 200, 0}, //   0 → 200 live — full ramp
		{"▼ 0", 0, 200},   // 200 →   0 live — all closed
	}

	var sessions []*sshSession
	connID := 0
	totalOpened := 0

	// Header
	t.Logf("")
	t.Logf("┌──────────┬────────┬────────┬───────┬────────────┬──────────────┬────────────────┐")
	t.Logf("│ %-8s │ %-6s │ %-6s │ %-5s │ %-10s │ %-12s │ %-14s │",
		"stage", "open", "close", "live", "goroutines", "heap", "Δ from base")
	t.Logf("├──────────┼────────┼────────┼───────┼────────────┼──────────────┼────────────────┤")
	t.Logf("│ %-8s │ %-6s │ %-6s │ %-5d │ %-10d │ %12s │ %14s │",
		"idle", "-", "-", 0, base.goroutines, fmtBytes(base.heapBytes), "-")

	for _, w := range waves {
		// ── Open ──────────────────────────────────────────────────
		opened := 0
		if w.open > 0 {
			var mu sync.Mutex
			var wg sync.WaitGroup
			for i := 0; i < w.open; i++ {
				wg.Add(1)
				sem <- struct{}{}
				go func(id int) {
					defer func() { <-sem }()
					defer wg.Done()
					s := dialSession(t, sshAddr, id)
					if s != nil {
						mu.Lock()
						sessions = append(sessions, s)
						opened++
						mu.Unlock()
					}
				}(connID)
				connID++
			}
			wg.Wait()
		}
		totalOpened += opened

		// ── Close ─────────────────────────────────────────────────
		toClose := w.close
		if toClose > len(sessions) {
			toClose = len(sessions)
		}
		for i := 0; i < toClose; i++ {
			sessions[i].close()
		}
		sessions = sessions[toClose:]

		// Let server-side goroutines from closed sessions drain.
		time.Sleep(1 * time.Second)

		// ── Measure ───────────────────────────────────────────────
		cur, err := collectStats(ctx, pprofAddr)
		if err != nil {
			t.Fatalf("%s stats: %v", w.name, err)
		}
		live := len(sessions)
		delta := cur.goroutines - base.goroutines

		t.Logf("│ %-8s │ %-6d │ %-6d │ %-5d │ %-10d │ %12s │ %+14d │",
			w.name, opened, toClose, live, cur.goroutines, fmtBytes(cur.heapBytes), delta)

		if delta > 30 && live == 0 {
			t.Errorf("%s: GOROUTINE LEAK: delta=%d with 0 live sessions — goroutines not returning to baseline",
				w.name, delta)
		}
	}

	t.Logf("└──────────┴────────┴────────┴───────┴────────────┴──────────────┴────────────────┘")
	t.Logf("")

	// Clean up remaining sessions.
	for _, s := range sessions {
		s.close()
	}
	sessions = nil

	// Final measurement after everything is closed.
	time.Sleep(2 * time.Second)
	final, err := collectStats(ctx, pprofAddr)
	if err == nil {
		t.Logf("final (all closed): %d goroutines, %s heap (baseline: %d, %s)",
			final.goroutines, fmtBytes(final.heapBytes),
			base.goroutines, fmtBytes(base.heapBytes))
		if final.goroutines-base.goroutines > 10 {
			t.Errorf("GOROUTINE LEAK after all sessions closed: delta=%d (expected <10)",
				final.goroutines-base.goroutines)
		}
	}

	t.Logf("total: %d sessions opened, all closed", totalOpened)
}
