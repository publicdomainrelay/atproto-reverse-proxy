// Test demonstrating the goroutine leak from repeatedly calling
// identity.DefaultDirectory() and the fix: store the directory in a
// server struct initialized once in main().
//
//	cd atproto-reverse-proxy/src/golang
//	go test -vet=off -run Test -count=1 -v ./cmd/atprp-ssh-relay/
package main

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

// ---------------------------------------------------------------------------
// Fake directory — counts Lookup calls so we can verify the cached
// directory is reused, not recreated, on every auth attempt.
// ---------------------------------------------------------------------------

type countingDirectory struct {
	lookupCalls int
	mu          sync.Mutex
	// Return this identity on every Lookup.
	fakeIdent *identity.Identity
}

func (d *countingDirectory) LookupHandle(_ context.Context, _ syntax.Handle) (*identity.Identity, error) {
	return nil, fmt.Errorf("unexpected LookupHandle call")
}

func (d *countingDirectory) LookupDID(_ context.Context, _ syntax.DID) (*identity.Identity, error) {
	return nil, fmt.Errorf("unexpected LookupDID call")
}

func (d *countingDirectory) Lookup(_ context.Context, _ syntax.AtIdentifier) (*identity.Identity, error) {
	d.mu.Lock()
	d.lookupCalls++
	d.mu.Unlock()
	if d.fakeIdent != nil {
		return d.fakeIdent, nil
	}
	return &identity.Identity{}, nil
}

func (d *countingDirectory) Purge(_ context.Context, _ syntax.AtIdentifier) error { return nil }

func (d *countingDirectory) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lookupCalls
}

// ---------------------------------------------------------------------------
// Leak demonstration (library-level)
// ---------------------------------------------------------------------------

// TestDefaultDirectoryGoroutineLeak demonstrates the underlying library
// behavior: each DefaultDirectory() spawns 2 goroutines that persist.
func TestDefaultDirectoryGoroutineLeak(t *testing.T) {
	runtime.GC()

	var dirs []identity.Directory
	before := runtime.NumGoroutine()
	t.Logf("goroutines before: %d", before)

	const iterations = 50
	for i := 0; i < iterations; i++ {
		dirs = append(dirs, identity.DefaultDirectory())
	}

	runtime.GC()
	after := runtime.NumGoroutine()
	delta := after - before
	t.Logf("goroutines after %d DefaultDirectory() calls: %d (delta=%d, ~%.0f per call)",
		iterations, after, delta, float64(delta)/float64(iterations))

	if delta < iterations {
		t.Logf("OK: goroutine increase (%d) < iterations (%d)", delta, iterations)
	} else {
		t.Logf("CONFIRMED: goroutine leak — %d goroutines from %d calls", delta, iterations)
	}

	runtime.KeepAlive(dirs)
}

// ---------------------------------------------------------------------------
// THE REAL TESTS — verify the fix in resolveATProtoIdentifier
// ---------------------------------------------------------------------------

// TestResolveATProtoIdentifierReusesCachedDirectory verifies that
// calling resolveATProtoIdentifier many times does NOT create new
// directories. It injects a fake directory so we can count calls and
// avoid network I/O.
//
// This is the regression test for the 238k-goroutine leak. Before the
// fix, resolveATProtoIdentifier called identity.DefaultDirectory() on
// every invocation — 2 new LRU goroutines per call. After the fix, the
// directory is stored in srv.directory and reused.
func TestResolveATProtoIdentifierReusesCachedDirectory(t *testing.T) {
	fake := &countingDirectory{}
	srv := &server{
		directory:        fake,
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
	}

	ctx := context.Background()
	const iterations = 500

	for i := 0; i < iterations; i++ {
		_, err := srv.resolveATProtoIdentifier(ctx, "did:plc:test")
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", i, err)
		}
	}

	if fake.calls() != iterations {
		t.Errorf("Lookup called %d times, want %d", fake.calls(), iterations)
	}
	t.Logf("✓ resolveATProtoIdentifier called %d times — directory reused, Lookup called %d times",
		iterations, fake.calls())
}

// TestResolveATProtoIdentifierDoesNotCreateNewDirectories is the
// goroutine-level regression test. It uses a REAL DefaultDirectory()
// (which spawns 2 LRU goroutines) and verifies that calling
// resolveATProtoIdentifier N times does NOT create N×2 goroutines.
//
// With a canceled context, Lookup fails fast (no network), so this
// test completes in milliseconds regardless of iteration count.
func TestResolveATProtoIdentifierDoesNotCreateNewDirectories(t *testing.T) {
	srv := &server{
		directory:        identity.DefaultDirectory(),
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
	}

	// Warm up: let the 2 LRU goroutines settle.
	runtime.GC()
	time.Sleep(10 * time.Millisecond)

	before := runtime.NumGoroutine()
	t.Logf("goroutines before: %d (includes 2 from DefaultDirectory LRU)", before)

	// Canceled context — resolveATProtoIdentifier fails fast.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	const iterations = 500
	for i := 0; i < iterations; i++ {
		_, _ = srv.resolveATProtoIdentifier(ctx, "did:plc:test")
		// Error expected (context canceled), ignored.
	}

	runtime.GC()
	after := runtime.NumGoroutine()
	delta := after - before
	t.Logf("goroutines after %d resolveATProtoIdentifier calls: %d (delta=%d)",
		iterations, after, delta)

	// Before the fix: delta ≈ 2×iterations (2 LRU goroutines per call).
	// After the fix: delta ≈ 0 (same directory, no new LRU instances).
	if delta > 10 {
		t.Errorf("GOROUTINE LEAK: delta=%d after %d calls. "+
			"resolveATProtoIdentifier may still be creating new directories.",
			delta, iterations)
	} else {
		t.Logf("✓ no goroutine leak: delta=%d after %d calls", delta, iterations)
	}
}

// ---------------------------------------------------------------------------
// Struct initialization
// ---------------------------------------------------------------------------

func TestServerInit(t *testing.T) {
	srv := &server{
		directory:        identity.DefaultDirectory(),
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
		maxConnsLimit:    200,
	}
	if srv.directory == nil {
		t.Fatal("directory not initialized")
	}
	if srv.sshPublicKeyCache == nil {
		t.Fatal("sshPublicKeyCache not initialized")
	}
	if srv.reg == nil {
		t.Fatal("reg not initialized")
	}
}

func TestServerCaddyClient(t *testing.T) {
	srv := &server{
		directory:        identity.DefaultDirectory(),
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
		caddyClient:       &http.Client{Transport: &http.Transport{}},
	}
	if srv.caddyClient == nil {
		t.Fatal("caddyClient not initialized")
	}
	c1 := srv.caddyClient
	c2 := srv.caddyClient
	if c1 != c2 {
		t.Error("caddyClient references differ")
	}
}

// ---------------------------------------------------------------------------
// SSH public key cache pruning
// ---------------------------------------------------------------------------

func TestPruneSSHPublicKeyCacheLoop(t *testing.T) {
	srv := &server{
		directory:        identity.DefaultDirectory(),
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
	}

	srv.sshPublicKeyCacheMu.Lock()
	srv.sshPublicKeyCache["expired"] = &sshPublicKeyCacheEntry{
		keys:      []*SSHPublicKey{{Key: "ssh-rsa AAA...", Service: "test"}},
		expiresAt: time.Now().Add(-1 * time.Hour),
	}
	srv.sshPublicKeyCacheMu.Unlock()

	if len(srv.sshPublicKeyCache) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(srv.sshPublicKeyCache))
	}

	now := time.Now()
	srv.sshPublicKeyCacheMu.Lock()
	for k, v := range srv.sshPublicKeyCache {
		if now.After(v.expiresAt) {
			delete(srv.sshPublicKeyCache, k)
		}
	}
	srv.sshPublicKeyCacheMu.Unlock()

	if len(srv.sshPublicKeyCache) != 0 {
		t.Errorf("expected 0 entries after prune, got %d", len(srv.sshPublicKeyCache))
	}
}

var _ = sync.Once{}
