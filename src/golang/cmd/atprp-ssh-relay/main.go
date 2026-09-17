// go run main.go
//
// ssh -NnT -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PasswordAuthentication=no -R my-cool-service:80:127.0.0.1:8080 johnandersen777.bsky.social@localhost
//
// python -m http.server 8080
//
// curl -v --unix-socket $(echo /tmp/ssh-fwd-*/tcp.sock) http://localhost
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bluesky-social/indigo/api/agnostic"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/pkg/errors"
)

// forward represents a single remote->local UNIX socket forward
// stored in a temporary directory on the server.
type forward struct {
	listener    net.Listener
	localPath   string
	serviceName string
	userHandle  string
}

// sshPublicKeyCacheEntry holds a cached getSSHPublicKeys result with expiry.
// A nil keys slice with a non-empty err means the last lookup failed —
// negative caching prevents auth storms from hammering the PDS on every
// reconnect attempt for the same failing DID.
type sshPublicKeyCacheEntry struct {
	keys      []*SSHPublicKey
	err       error
	expiresAt time.Time
}

// server holds shared state initialized once in main() and threaded through
// the call graph explicitly — no package-level sync.Once singletons.
type server struct {
	// ATProto identity directory. identity.DefaultDirectory() creates
	// expirable LRU caches each backed by a background goroutine.
	// Creating one per auth attempt leaks goroutines (observed: 238k).
	directory identity.Directory

	// HTTP client for the Caddy admin Unix socket. Reused by all
	// forward configure/unconfigure/reconcile calls.
	caddyClient *http.Client

	// SSH public key cache guards against repeated PDS lookups for the
	// same DID during auth storms.
	sshPublicKeyCacheMu sync.RWMutex
	sshPublicKeyCache   map[string]*sshPublicKeyCacheEntry

	// Forward registry for the reconcile loop.
	regMu sync.Mutex
	reg   map[string]*forward

	activeConns   int64
	maxConnsLimit int64
}

const (
	sshPublicKeyCacheTTL       = 5 * time.Minute
	sshPublicKeyNegCacheTTL    = 30 * time.Second
	maxConcurrentHandshakes    = 50
)

func forwardKey(f *forward) string { return f.serviceName + "\x00" + f.userHandle }

func main() {
	log.Println("▶️ Starting SSH-forward server")

	if os.Getenv("GOMEMLIMIT") == "" {
		log.Println("⚠️ GOMEMLIMIT not set — Go heap may grow until kernel OOM. Set GOMEMLIMIT=3GiB or similar.")
	}

	srv := &server{
		directory:        identity.DefaultDirectory(),
		sshPublicKeyCache: make(map[string]*sshPublicKeyCacheEntry),
		reg:              make(map[string]*forward),
		maxConnsLimit:    200,
	}
	if s := os.Getenv("CADDY_SOCK"); s != "" {
		srv.caddyClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", s)
				},
			},
		}
	}

	signer, err := loadOrGenerateHostKey("host_key")
	if err != nil {
		log.Fatalf("❌ host key load/generate failed: %v", err)
	}

	// TEST_ACCEPT_ANY_KEY bypasses ATProto identity + PDS key resolution
	// and accepts any SSH key for any user, with a wildcard service ("*").
	// Only for integration testing — never set in production.
	testAcceptAnyKey := os.Getenv("TEST_ACCEPT_ANY_KEY") == "1"

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if testAcceptAnyKey {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp":                 ssh.FingerprintSHA256(pubKey),
						"pubkey-valid-for-services": "*",
					},
				}, nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			log.Printf("Resolving DID PLC and PDS for user=%s", c.User())
			ident, err := srv.resolveATProtoIdentifier(ctx, c.User())
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("Failed to resolve DID PLC and PDS for user=%s: %v", c.User()))
			}
			pds := ident.PDSEndpoint()
			if pds == "" {
				return nil, errors.Wrap(err, fmt.Sprintf("Could not find PDS for user=%s", c.User()))
			}
			log.Printf("Got DID PLC and PDS for user=%s did=%s pds=%s", c.User(), ident.DID, pds)

			log.Printf("Resolving public keys for user=%s", c.User())
			sshPublicKeys, err := srv.cachedGetSSHPublicKeys(ctx, pds, ident.DID.String())
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("Failed get ssh public keys for user=%s: %v", c.User(), err))
			}
			log.Printf("Got ssh public keys for user=%s sshPublicKeys=%+v", c.User(), sshPublicKeys)

			services := make([]string, 0)

			for _, sshPublicKey := range sshPublicKeys {
				authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPublicKey.Key))
				if err != nil {
					log.Printf("error parsing ssh public key for user=%s key=%s: %v", c.User(), sshPublicKey.Key, err)
					continue
				}

				if string(authorizedKey.Marshal()) == string(pubKey.Marshal()) {
					log.Printf("key is valid for service=%s", sshPublicKey.Service)
					services = append(services, sshPublicKey.Service)
				}
			}
			if len(services) > 0 {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp":                 ssh.FingerprintSHA256(pubKey),
						"pubkey-valid-for-services": strings.Join(services, ","),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}
	cfg.AddHostKey(signer)

	sshAddr := os.Getenv("SSH_LISTEN_ADDR")
	if sshAddr == "" {
		sshAddr = ":2222"
	}
	ln, err := net.Listen("tcp", sshAddr)
	if err != nil {
		log.Fatalf("❌ listen tcp %s: %v", sshAddr, err)
	}
	log.Printf("✅ SSH listening on %s", ln.Addr())

	// pprof server on loopback for live heap/goroutine profiling.
	go func() {
		pprofAddr := os.Getenv("PPROF_LISTEN_ADDR")
		if pprofAddr == "" {
			pprofAddr = "127.0.0.1:6060"
		}
		pprofLn, err := net.Listen("tcp", pprofAddr)
		if err != nil {
			log.Printf("⚠️ pprof listen %s failed: %v", pprofAddr, err)
			return
		}
		log.Printf("🔬 pprof listening on %s", pprofLn.Addr())
		http.Serve(pprofLn, nil)
	}()

	// Reconcile loop keeps Caddy's dynamic config in sync. If CADDY_SOCK
	// is unset the loop is a no-op (srv.caddyClient is nil).
	if srv.caddyClient != nil {
		go srv.reconcileLoop()
		log.Println("♻️ started Caddy reconcile loop")
	} else {
		log.Println("⚠️ CADDY_SOCK unset — Caddy reconciliation disabled")
	}

	// Periodically force Go to return unused heap to the OS.
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			debug.FreeOSMemory()
			log.Println("🧹 returned unused heap to OS")
		}
	}()

	// Prune expired sshPublicKeyCache entries.
	go srv.pruneSSHPublicKeyCacheLoop()

	handshakeSem := make(chan struct{}, maxConcurrentHandshakes)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("⚠️ accept error: %v", err)
			continue
		}

		n := atomic.AddInt64(&srv.activeConns, 1)
		if n > srv.maxConnsLimit {
			atomic.AddInt64(&srv.activeConns, -1)
			conn.Close()
			if n%50 == 1 {
				log.Printf("🚫 dropping connection — at limit (%d/%d)", n, srv.maxConnsLimit)
			}
			continue
		}

		handshakeSem <- struct{}{}
		go func() {
			defer func() { <-handshakeSem }()
			defer atomic.AddInt64(&srv.activeConns, -1)
			srv.handleSSH(conn, cfg)
		}()
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	log.Printf("ℹ️ host_key not found — generating ephemeral RSA key")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER})
	return ssh.ParsePrivateKey(privPEM)
}

type TCPIPForward struct {
	BindAddr   string
	BindPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (srv *server) handleSSH(raw net.Conn, cfg *ssh.ServerConfig) {
	defer raw.Close()
	log.Printf("🔌 New raw connection from %s", raw.RemoteAddr())

	ctx, cancel := context.WithCancel(context.Background())
	serverConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		log.Printf("❌ SSH handshake failed: %v", err)
		cancel()
		return
	}
	log.Printf("✅ SSH handshake OK — user=%s", serverConn.User())
	go func() { serverConn.Wait(); cancel() }()

	// Send SSH-level keepalives so the underlying TCP connection never goes
	// silent long enough to be idle-closed by network intermediaries (~18s).
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _, err := serverConn.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					log.Printf("⚠️ keepalive failed for user=%s: %v", serverConn.User(), err)
					cancel()
					return
				}
			}
		}
	}()

	// ignore channels
	go func() {
		for newChan := range chans {
			switch newChan.ChannelType() {
			default:
				log.Printf("❌ rejecting channel type=%s", newChan.ChannelType())
				newChan.Reject(ssh.UnknownChannelType, "unsupported channel")
			}
		}
	}()

	tmpDir, err := os.MkdirTemp("", "ssh-fwd-*")
	if err != nil {
		log.Printf("❌ temp dir creation failed: %v", err)
		return
	}
	log.Printf("📂 using temp dir %s", tmpDir)
	defer os.RemoveAll(tmpDir)

	forwards := make(map[string]*forward)
	var mu sync.Mutex

	// TODO If we do not get a request for forwarding to serviceName in X seconds,
	// cancel the connection/context and return.
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			var p TCPIPForward
			_ = ssh.Unmarshal(req.Payload, &p)

			base := "tcp.sock"
			localPath := filepath.Join(tmpDir, base)
			log.Printf("📨 tcpip-forward request: %s:%d → local=%s", p.BindAddr, p.BindPort, localPath)

			pubkeyValidForServices := strings.Split(serverConn.Permissions.Extensions["pubkey-valid-for-services"], ",")
			found := false
			for _, pubkeyValidForService := range pubkeyValidForServices {
				if pubkeyValidForService == "*" || pubkeyValidForService == p.BindAddr {
					found = true
					break
				}
			}
			if !found {
				log.Printf("public key not valid for service=%s is valid_for=%+v", p.BindAddr, pubkeyValidForServices)
				req.Reply(false, nil)
				continue
			}

			listener, err := net.Listen("unix", localPath)
			if err != nil {
				log.Printf("❌ failed to listen on %s: %v", localPath, err)
				req.Reply(false, nil)
				continue
			}

			f := &forward{
				listener:    listener,
				localPath:   localPath,
				serviceName: p.BindAddr,
				userHandle:  serverConn.User(),
			}
			err = srv.configureNewForward(ctx, f)
			if err != nil {
				log.Printf("❌ failed to setup caddy forward for %s: %v", p.BindAddr, err)
				listener.Close()
				req.Reply(false, nil)
				continue
			}
			mu.Lock()
			forwards[f.serviceName] = f
			mu.Unlock()

			req.Reply(true, nil)

			go acceptTCPLoop(ctx, listener, serverConn, &p)

		case "cancel-tcpip-forward":
			var p TCPIPForward
			_ = ssh.Unmarshal(req.Payload, &p)
			log.Printf("📨 cancel-tcpip-forward request: %s:%d", p.BindAddr, p.BindPort)

			mu.Lock()
			if f, ok := forwards[p.BindAddr]; ok {
				f.listener.Close()
				ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
				err := srv.unconfigureForward(ctx, f)
				if err != nil {
					log.Printf("failed to removed forward %+v: %+v", f, err)
				}
				delete(forwards, f.serviceName)
				log.Printf("🗑 removed forward %+v", f)
			}
			mu.Unlock()
			req.Reply(true, nil)

		default:
			log.Printf("❓ unknown request: %s", req.Type)
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	<-ctx.Done()
	log.Println("🔒 SSH session closed, cleaning up...")

	// Remove from Caddy
	mu.Lock()
	for _, f := range forwards {
		f.listener.Close()
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		err := srv.unconfigureForward(ctx, f)
		if err != nil {
			log.Printf("failed to removed forward %+v: %+v", f, err)
		}
		delete(forwards, f.serviceName)
		log.Printf("🗑 removed forward %+v", f)
	}
	mu.Unlock()

	log.Println("🔒 SSH session closed, cleaned up")
}

func acceptTCPLoop(ctx context.Context, listener net.Listener, sc *ssh.ServerConn, f *TCPIPForward) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("ℹ️ TCP proxy listener closed for %s:%d", f.BindAddr, f.BindPort)
			return
		}
		log.Printf("🔗 incoming connection on %s (TCP forward to %s:%d)", listener.Addr(), f.BindAddr, f.BindPort)
		go handleTCPConn(ctx, conn, sc, f)
	}
}

func handleTCPConn(ctx context.Context, conn net.Conn, sc *ssh.ServerConn, f *TCPIPForward) {
	defer conn.Close()
	log.Printf("↔ proxying TCP data for %s:%d", f.BindAddr, f.BindPort)

	payload := ssh.Marshal(TCPIPForward{
		BindAddr:   f.BindAddr,
		BindPort:   f.BindPort,
		OriginAddr: "127.0.0.1",
		OriginPort: f.BindPort,
	})

	channel, reqs, err := sc.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		log.Printf("❌ OpenChannel forwarded-tcpip failed for %s:%d: %v", f.BindAddr, f.BindPort, err)
		return
	}
	go ssh.DiscardRequests(reqs)

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, channel)
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
	channel.Close()
	log.Printf("✅ closed TCP proxy for %s:%d", f.BindAddr, f.BindPort)
}


// ensureSrv0Exists checks if srv0 is initialized and creates it if not.
// When CF_API_TOKEN is set, it also installs the TLS automation policy that
// manages a SINGLE "*.THIS_ENDPOINT" wildcard cert via the Cloudflare DNS-01
// challenge. Every normal service is served under one flattened label
// (svc--handle.THIS_ENDPOINT), so that one wildcard cert covers them all and
// no per-name issuance happens. The policy also keeps on_demand enabled as a
// fallback (gated by on_demand_tls.ask) for explicit "*.service" child
// wildcards not covered by the shared cert.
//
// Note: the wildcard catch-all route is NOT installed here. Callers must call
// ensureCatchAllRoute after all per-forward routes have been appended so that
// the catch-all always sorts last.
// patchSrv0IdleTimeout disables idle_timeout on an already-existing srv0 so
// WebSocket connections are never idle-closed by Caddy (Caddy ignores WS ping
// frames as activity). "0" means disabled; dead peers are caught at the TCP
// level via OS keepalives. Only PATCH when it isn't already "0": every write
// reloads Caddy's config and cancels in-flight ACME orders, so an unconditional
// per-tick PATCH would starve HTTP-01 issuance.
func patchSrv0IdleTimeout(ctx context.Context, client *http.Client, respBody []byte) {
	var srv struct {
		IdleTimeout json.RawMessage `json:"idle_timeout"`
	}
	_ = json.Unmarshal(respBody, &srv)
	// Caddy serializes a 0 caddy.Duration as omitempty, so a disabled
	// idle_timeout returns as an absent key (nil RawMessage) or JSON
	// null — both mean "already disabled".
	idle := string(srv.IdleTimeout)
	if idle == `"0"` || idle == "0" || idle == "" || idle == "null" {
		return
	}
	patchBody, _ := json.Marshal("0")
	patchReq, _ := http.NewRequestWithContext(ctx, "PATCH",
		"http://127.0.0.1/config/apps/http/servers/srv0/idle_timeout",
		bytes.NewReader(patchBody))
	patchReq.Header.Set("Content-Type", "application/json")
	pr, err := client.Do(patchReq)
	if err != nil {
		log.Printf("❌ idle_timeout PATCH failed: %v — WS connections may drop on idle", err)
		return
	}
	if pr.StatusCode >= 300 {
		body, _ := io.ReadAll(pr.Body)
		log.Printf("❌ idle_timeout PATCH non-success %d: %s — WS connections may drop on idle", pr.StatusCode, string(body))
	}
	pr.Body.Close()
}

func ensureSrv0Exists(ctx context.Context, client *http.Client) error {
	// Try GET first. If srv0 exists, Caddy already loaded the Caddyfile and
	// populated the static routes (xrpc, rp, etc.). Patch idle_timeout and
	// return — never touch the routes array.
	checkReq, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/config/apps/http/servers/srv0", nil)
	resp, err := client.Do(checkReq)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			patchSrv0IdleTimeout(ctx, client, body)
			return ensureWildcardTLSPolicy(ctx, client)
		}
	}

	// srv0 does not exist yet. Wait for Caddy to load the Caddyfile (which
	// creates srv0 with the static routes from the Caddyfile). If the relay
	// creates srv0 first via the admin API with an empty routes array, Caddy
	// will never apply the Caddyfile's static site blocks — they all route
	// through the API-created srv0. Retry for up to 10 s; only fall back to
	// creating an empty srv0 if Caddy never materializes one.
	const retryInterval = 500 * time.Millisecond
	const maxRetries = 20 // 10 s total
	for attempt := 0; attempt < maxRetries; attempt++ {
		time.Sleep(retryInterval)
		checkReq, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/config/apps/http/servers/srv0", nil)
		resp, err := client.Do(checkReq)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				log.Printf("caddy srv0 appeared after %dms (Caddyfile loaded)", (attempt+1)*500)
				patchSrv0IdleTimeout(ctx, client, body)
				return ensureWildcardTLSPolicy(ctx, client)
			}
		}
	}

	// Timed out waiting for Caddy — create srv0 as fallback. Static Caddyfile
	// routes (xrpc.fedproxy.com, rp.fedproxy.com, etc.) will NOT be present;
	// they must be re-added dynamically or via a subsequent Caddy reload.
	log.Println("caddy creating srv0 (Caddyfile did not load in time — static routes will be missing)")

	// idle_timeout "0" disables the HTTP idle timer entirely.
	srvPayload := map[string]any{
		"listen":       []string{":443"},
		"routes":       []any{},
		"idle_timeout": "0",
	}

	body, _ := json.Marshal(srvPayload)
	// Create srv0. The "..." in the path ensures intermediate keys like 'apps' and 'http' are created if missing.
	setupReq, err := http.NewRequestWithContext(ctx, "POST", "http://127.0.0.1/config/apps/http/servers/srv0", bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "error building request to create srv0")
	}
	setupReq.Header.Set("Content-Type", "application/json")

	setupResp, err := client.Do(setupReq)
	if err != nil {
		return errors.Wrap(err, "error creating srv0")
	}
	defer setupResp.Body.Close()
	log.Println("created srv0")
	return ensureWildcardTLSPolicy(ctx, client)
}

// ensureWildcardTLSPolicy installs the DNS-01 TLS automation policy and
// triggers issuance of the shared "*.<endpoint>" wildcard cert. No-op when
// CF_API_TOKEN is unset. Does NOT touch the catch-all route — call
// ensureCatchAllRoute separately, after all per-forward routes are in place.
func ensureWildcardTLSPolicy(ctx context.Context, client *http.Client) error {
	cfToken := os.Getenv("CF_API_TOKEN")
	if cfToken == "" {
		return nil
	}
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set")
	}

	policyID := "tls-policy-wildcard-" + thisEndpoint
	wildcard := "*." + thisEndpoint

	// Guard the policy WRITE only, not this whole function. Rewriting the policy
	// every reconcile tick reloads Caddy's config every 30s, and each reload
	// cancels in-flight ACME orders. The cert registration below must still run
	// on every pass: gating it behind this same early return is exactly how the
	// wildcard was left unmanaged, unrenewed, and eventually deleted.
	if !idExists(ctx, client, policyID) {
		// One DNS-01 (Cloudflare) automation policy, subject-less so it's Caddy's
		// default issuer. on_demand stays enabled as a FALLBACK — gated by
		// on_demand_tls.ask — for names not covered by the shared wildcard, e.g. an
		// explicit "*.service" child wildcard. Normal flattened hosts never reach
		// on_demand: the shared "*.<endpoint>" wildcard cert (automated below)
		// is already loaded and served for them, so no per-name ACME happens.
		policy := map[string]any{
			"@id":       policyID,
			"on_demand": true,
			"issuers": []map[string]any{
				{
					"module": "acme",
					"challenges": map[string]any{
						"dns": map[string]any{
							"provider": map[string]any{
								"name":      "cloudflare",
								"api_token": cfToken,
							},
						},
					},
				},
			},
		}
		if err := upsertAutomationPolicy(ctx, client, policyID, policy); err != nil {
			return errors.Wrap(err, "ensure tls automation policy")
		}
	}

	// Register the shared wildcard with Caddy's cert automator so every
	// flattened svc--handle host is served from it (no per-name ACME). This is
	// what puts the cert under Caddy's maintenance, and a cert Caddy does not
	// manage is a cert Caddy will not renew: the wildcard has no site block, so
	// nothing else ever asks Caddy for it. Cheap once registered (one GET).
	triggerCertIssuance(ctx, client, wildcard)
	return nil
}

// ensureCatchAllRoute appends (or re-appends) the wildcard catch-all 404 route
// to the END of srv0's routes array. It unconditionally deletes any existing
// copy first, then re-appends, so the catch-all always sorts after every
// per-forward route regardless of insertion order. Callers must invoke this
// AFTER all per-forward routes have been pushed for a given operation.
// No-op when CF_API_TOKEN or THIS_ENDPOINT is unset.
func ensureCatchAllRoute(ctx context.Context, client *http.Client) error {
	cfToken := os.Getenv("CF_API_TOKEN")
	if cfToken == "" {
		return nil
	}
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set")
	}

	routeID := "route-wildcard-catchall-" + thisEndpoint
	route := map[string]any{
		"@id": routeID,
		"match": []map[string]any{
			{"host": []string{"*." + thisEndpoint}},
		},
		"handle": []map[string]any{
			{
				"handler":     "static_response",
				"status_code": 404,
				"body":        "no route configured for host\n",
			},
		},
		"terminal": true,
	}
	if err := upsertByID(ctx, client, routeID,
		"http://127.0.0.1/config/apps/http/servers/srv0/routes", route); err != nil {
		return errors.Wrap(err, "ensure wildcard catch-all route")
	}
	return nil
}

// upsertAutomationPolicy idempotently inserts or replaces an automation
// policy in `apps/tls/automation/policies`. POST-append is unreliable here
// because the path may not yet exist as an array (Caddyfile-derived configs
// often omit it), so we read-modify-write: GET the current array, drop any
// element with the same @id, append ours, then PATCH (when the path exists)
// or PUT (when it doesn't) the whole array back. Existing policies are kept
// byte-for-byte via json.RawMessage.
func upsertAutomationPolicy(ctx context.Context, client *http.Client, id string, policy map[string]any) error {
	const url = "http://127.0.0.1/config/apps/tls/automation/policies"

	var existing []json.RawMessage
	pathExists := false
	getReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "build get policies request")
	}
	if resp, err := client.Do(getReq); err == nil {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		trimmed := strings.TrimSpace(string(data))
		if resp.StatusCode == http.StatusOK && trimmed != "" && trimmed != "null" {
			pathExists = true
			if err := json.Unmarshal(data, &existing); err != nil {
				return errors.Wrap(err, "decode existing policies")
			}
		}
	}

	filtered := make([]json.RawMessage, 0, len(existing)+1)
	for _, raw := range existing {
		var peek struct {
			ID string `json:"@id"`
		}
		_ = json.Unmarshal(raw, &peek)
		if peek.ID == id {
			continue
		}
		filtered = append(filtered, raw)
	}
	ourBytes, err := json.Marshal(policy)
	if err != nil {
		return errors.Wrap(err, "marshal policy")
	}
	filtered = append(filtered, ourBytes)

	body, err := json.Marshal(filtered)
	if err != nil {
		return errors.Wrap(err, "marshal policies array")
	}
	// PATCH replaces an existing value; PUT creates one (and 409s if the
	// path already exists). Pick based on whether GET found anything.
	method := "PUT"
	if pathExists {
		method = "PATCH"
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "build policies request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "write policies")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// upsertByID DELETEs any existing config object with the given @id, then
// POSTs the payload to arrayURL (which must be an array path; POST appends).
// A 404 on DELETE is fine — it just means the object doesn't exist yet.
func upsertByID(ctx context.Context, client *http.Client, id, arrayURL string, payload any) error {
	delReq, err := http.NewRequestWithContext(ctx, "DELETE", "http://127.0.0.1/id/"+id, nil)
	if err != nil {
		return errors.Wrap(err, "build delete request")
	}
	if delResp, err := client.Do(delReq); err == nil {
		io.Copy(io.Discard, delResp.Body)
		delResp.Body.Close()
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "marshal payload")
	}
	req, err := http.NewRequestWithContext(ctx, "POST", arrayURL, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "build post request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "post payload")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// flattenLabel folds an identity part that may contain dots or colons (a handle
// like "alice.bsky.social", a dotted service name, or a bare DID used as the SSH
// username like "did:plc:abc123") into a single DNS label by replacing each dot
// and colon with a dash. Colons appear when the SSH username is a raw DID, which
// is otherwise an invalid DNS label.
func flattenLabel(s string) string {
	return strings.NewReplacer(".", "-", ":", "-").Replace(s)
}

// serviceLabel builds the flattened single DNS label "<service>--<handle>"
// (dots -> dashes). Folding the whole identity into one label (instead of
// "<service>.<handle>.<endpoint>") puts the host exactly one level under
// <endpoint>, so it is covered by the single shared "*.<endpoint>" wildcard
// cert and needs no per-name ACME. The "--" separator keeps service and handle
// visually distinct. A DNS label is capped at 63 chars; configureNewForward
// rejects forwards whose label would exceed that.
func serviceLabel(service, handle string) string {
	return flattenLabel(service) + "--" + flattenLabel(handle)
}

// forwardFQDNs returns the host names a forward is served under.
//
//   - Normal service "app"  -> "app--<handle>.<endpoint>" (one label). Served
//     off the shared "*.<endpoint>" wildcard cert, so no per-name ACME.
//   - Explicit wildcard "*.app" (client bound "-R *.app:80:...") ->
//     "*.app--<handle>.<endpoint>", a genuine child wildcard so the client can
//     serve arbitrary sub-hosts. Two labels deep, NOT under "*.<endpoint>", so
//     it gets its OWN DNS-01 wildcard cert — the one case the on_demand_tls ask
//     gate still backs.
//
// A bare "*" service (key valid for ALL services) is an auth wildcard, not a
// host, and never reaches here as a real forward's serviceName.
func forwardFQDNs(f *forward, thisEndpoint string) []string {
	if rest, ok := strings.CutPrefix(f.serviceName, "*."); ok {
		return []string{"*." + serviceLabel(rest, f.userHandle) + "." + thisEndpoint}
	}
	return []string{serviceLabel(f.serviceName, f.userHandle) + "." + thisEndpoint}
}

func (srv *server) configureNewForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}
	caddySockPath := os.Getenv("CADDY_SOCK")
	if caddySockPath == "" {
		return fmt.Errorf("CADDY_SOCK must be set")
	}
	client := srv.caddyClient

	// Ensure srv0 + the wildcard DNS-01 policy + catch-all exist before
	// posting routes (avoids a 404 on the routes array, and guarantees the
	// on_demand policy the cert gate depends on is present).
	if err := ensureSrv0Exists(ctx, srv.caddyClient); err != nil {
		return errors.Wrap(err, "failed to ensure srv0 existence")
	}

	// Reject forwards whose flattened "<service>--<handle>" label would exceed
	// the DNS 63-char label limit — it'd be an invalid, unroutable hostname.
	svc := strings.TrimPrefix(f.serviceName, "*.")
	if label := serviceLabel(svc, f.userHandle); len(label) > 63 {
		return fmt.Errorf("flattened service label %q is %d chars, over the 63-char DNS label limit (service=%q handle=%q)", label, len(label), f.serviceName, f.userHandle)
	}

	for _, fqdn := range forwardFQDNs(f, thisEndpoint) {
		if err := ensureForwardRoute(ctx, srv.caddyClient, fqdn, f.localPath); err != nil {
			return errors.Wrap(err, fmt.Sprintf("error configuring caddy for fqdn=%s", fqdn))
		}
		// Normal flattened hosts ride the shared "*.<endpoint>" wildcard cert,
		// so they need no issuance. An explicit "*.service" child wildcard is
		// two labels deep and NOT covered by it, so mint its own DNS-01 cert.
		if strings.HasPrefix(fqdn, "*.") {
			triggerCertIssuance(ctx, client, fqdn)
		}
	}

	// Re-append catch-all AFTER the new forward route so it stays last.
	if err := ensureCatchAllRoute(ctx, srv.caddyClient); err != nil {
		return errors.Wrap(err, "ensure catch-all route after forward")
	}

	// Record the forward so the reconcile loop re-pushes its routes if Caddy
	// is restarted and loses them. Must happen AFTER all fallible operations
	// so a partial failure does not leak a stale entry in the global map.
	srv.regMu.Lock()
	srv.reg[forwardKey(f)] = f
	srv.regMu.Unlock()

	return nil
}

// ensureForwardRoute upserts the reverse-proxy route for a single fqdn at
// index 0 of srv0 so it matches before the terminal wildcard catch-all.
func ensureForwardRoute(ctx context.Context, client *http.Client, fqdn, localPath string) error {
	routeID := "route-" + fqdn
	routePayload := map[string]any{
		"@id": routeID,
		"match": []map[string]any{
			{"host": []string{fqdn}},
		},
		"handle": []map[string]any{
			{
				"handler": "subroute",
				"routes": []map[string]any{
					{
						"handle": []map[string]any{
							{
								"handler":            "reverse_proxy",
								"flush_interval":     -1,
								"stream_close_delay": "5m",
								"upstreams": []map[string]any{
									{"dial": "unix/" + localPath},
								},
								"transport": map[string]any{
									"protocol": "http",
									"keep_alive": map[string]any{
										"enabled":        true,
										"probe_interval": "30s",
									},
								},
							},
						},
					},
				},
			},
		},
		"terminal": true,
	}

	// Remove any stale copy first (idempotent: 404 is fine), then insert.
	delReq, err := http.NewRequestWithContext(ctx, "DELETE", "http://127.0.0.1/id/"+routeID, nil)
	if err != nil {
		return errors.Wrap(err, "build delete request")
	}
	if delResp, err := client.Do(delReq); err == nil {
		io.Copy(io.Discard, delResp.Body)
		delResp.Body.Close()
	}

	body, err := json.Marshal(routePayload)
	if err != nil {
		return errors.Wrap(err, "marshal route payload")
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		"http://127.0.0.1/config/apps/http/servers/srv0/routes", bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "build route post request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "post route")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned non-success status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// triggerCertIssuance best-effort adds the name to Caddy's automated-cert list
// so DNS-01 issuance starts immediately rather than on the first handshake, and
// so Caddy keeps renewing it afterwards. Used for the shared "*.<endpoint>"
// wildcard and for explicit "*.service" child wildcards (which on_demand cannot
// mint). Best-effort: errors non-fatal.
//
// The list is a single JSON array at apps/tls/certificates/automate, so a blind
// write would drop names registered by earlier calls (the wildcard plus every
// child wildcard). Read it first and write the union: PUT creates the entry,
// PATCH replaces it. POST is not a config-write verb here and Caddy rejects it
// with "invalid traversal path", which is why the wildcard was never obtained.
func triggerCertIssuance(ctx context.Context, client *http.Client, fqdn string) {
	const url = "http://127.0.0.1/config/apps/tls/certificates/automate"

	var subjects []string
	pathExists := false
	getReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	if resp, err := client.Do(getReq); err == nil {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		trimmed := strings.TrimSpace(string(data))
		if resp.StatusCode == http.StatusOK && trimmed != "" && trimmed != "null" {
			pathExists = true
			if err := json.Unmarshal(data, &subjects); err != nil {
				log.Printf("⚠️ cert automation: decoding existing list: %v", err)
				return
			}
		}
	}
	for _, s := range subjects {
		if s == fqdn {
			return
		}
	}

	body, err := json.Marshal(append(subjects, fqdn))
	if err != nil {
		return
	}
	method := "PUT"
	if pathExists {
		method = "PATCH"
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		log.Printf("⚠️ cert automation for %s returned %d", fqdn, resp.StatusCode)
		return
	}
	log.Printf("🔐 enabled Caddy cert automation for %s", fqdn)
}

// idExists reports whether Caddy has a config object with the given @id.
func idExists(ctx context.Context, client *http.Client, id string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/id/"+id, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

// reconcileLoop keeps Caddy's dynamic config in sync with this relay's view of
// the world. Caddy can be restarted independently (a deploy does exactly
// this), which drops the wildcard DNS-01 policy, the catch-all, and every
// per-forward route — and the relay's live SSH sessions would never re-push
// them on their own. Every tick it reinstalls the base config and any missing
// forward routes. Steady-state ticks are GET-only, so this is cheap.
func (srv *server) reconcileLoop() {
	const interval = 30 * time.Second
	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			defer cancel()

			if err := ensureSrv0Exists(ctx, srv.caddyClient); err != nil {
				log.Printf("⚠️ reconcile base config: %v", err)
				return
			}

			thisEndpoint := os.Getenv("THIS_ENDPOINT")
			srv.regMu.Lock()
			fwds := make([]*forward, 0, len(srv.reg))
			for _, f := range srv.reg {
				fwds = append(fwds, f)
			}
			srv.regMu.Unlock()

			appended := false
			for _, f := range fwds {
				for _, fqdn := range forwardFQDNs(f, thisEndpoint) {
					if idExists(ctx, srv.caddyClient, "route-"+fqdn) {
						continue
					}
					if err := ensureForwardRoute(ctx, srv.caddyClient, fqdn, f.localPath); err != nil {
						log.Printf("⚠️ reconcile route %s: %v", fqdn, err)
						continue
					}
					appended = true
					log.Printf("♻️ reconciled missing route %s", fqdn)
				}
			}

			// Re-append catch-all last so it never blocks per-forward routes,
			// but ONLY when we actually appended a forward route this tick (the
			// catch-all must sort after every specific route) or the catch-all
			// is missing entirely. Re-appending unconditionally would rewrite
			// Caddy's config every tick — each config reload cancels in-flight
			// ACME orders, so any HTTP-01 cert never gets a full issuance
			// window. Skipping the write keeps steady-state ticks GET-only.
			catchAllID := "route-wildcard-catchall-" + thisEndpoint
			if appended || !idExists(ctx, srv.caddyClient, catchAllID) {
				if err := ensureCatchAllRoute(ctx, srv.caddyClient); err != nil {
					log.Printf("⚠️ reconcile catch-all route: %v", err)
				}
			}
		}()
		time.Sleep(interval)
	}
}

func (srv *server) unconfigureForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}

	// Stop reconciling this forward before tearing its routes down, so the
	// loop doesn't race to re-add what we're removing.
	srv.regMu.Lock()
	if srv.reg[forwardKey(f)] == f {
		delete(srv.reg, forwardKey(f))
	}
	srv.regMu.Unlock()

	fqdns := forwardFQDNs(f, thisEndpoint)
	for _, fqdn := range fqdns {
		routeID := "route-" + fqdn

		caddySockPath := os.Getenv("CADDY_SOCK")
		if caddySockPath == "" {
			return fmt.Errorf("CADDY_SOCK must be set")
		}

		client := srv.caddyClient

		// Direct DELETE using the Caddy ID shortcut removes it instantly
		req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("http://127.0.0.1/id/%s", routeID), nil)
		if err != nil {
			return errors.Wrap(err, "failed to create delete request")
		}

		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("error removing caddy config for fqdn=%s", fqdn))
		}
		defer resp.Body.Close()

		// A 404 indicates it was already successfully removed (or never existed).
		if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotFound {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("caddy returned non-success status %d: %s", resp.StatusCode, string(respBody))
		}
	}

	return nil
}

// ATProto

// Data holds fedproxy specific data
type Data struct {
	SSHPublicKeys []*SSHPublicKey `json:"sshPublicKeys"`
}

type SSHPublicKey struct {
	Type      string `json:"$type"`
	Key       string `json:"key"`
	Name      string `json:"name"`
	Service   string `json:"service"`
	CreatedAt string `json:"createdAt"`
}

func (k *SSHPublicKey) ATProtoDecode(rec *agnostic.RepoListRecords_Record) error {
	if rec == nil || rec.Value == nil {
		return fmt.Errorf("error decoding ATProto SSHPublicKey record has no value")
	}

	if err := json.Unmarshal(*rec.Value, k); err != nil {
		return errors.Wrap(err, fmt.Sprintf("error decoding ATProto SSHPublicKey json.Unmarshal"))
	}

	return nil
}

// pruneSSHPublicKeyCacheLoop periodically removes expired entries from the
// SSH public key cache so cached key blobs don't accumulate forever.
func (srv *server) pruneSSHPublicKeyCacheLoop() {
	for {
		time.Sleep(5 * time.Minute)
		now := time.Now()
		srv.sshPublicKeyCacheMu.Lock()
		for k, v := range srv.sshPublicKeyCache {
			if now.After(v.expiresAt) {
				delete(srv.sshPublicKeyCache, k)
			}
		}
		n := len(srv.sshPublicKeyCache)
		srv.sshPublicKeyCacheMu.Unlock()
		if n > 0 {
			log.Printf("🧹 sshPublicKeyCache pruned, %d entries remaining", n)
		}
	}
}

func (srv *server) resolveATProtoIdentifier(ctx context.Context, inputId string) (*identity.Identity, error) {
	id, err := syntax.ParseAtIdentifier(inputId)
	if err != nil {
		return nil, err
	}
	slog.Info("valid syntax", "at-identifier", id)

	// DefaultDirectory returns a CacheDirectory wrapping BaseDirectory.
	// Each CacheDirectory creates two expirable LRU caches backed by a
	// background goroutine. Call once and reuse — creating one per auth
	// attempt leaks goroutines unboundedly.
	// srv.directory was initialized once in main()
	ident, err := srv.directory.Lookup(ctx, id)
	if err != nil {
		return nil, err
	}

	return ident, nil
}

// cachedGetSSHPublicKeys wraps getSSHPublicKeys with an in-memory TTL cache
// keyed by DID. Under an SSH auth storm the same DIDs are looked up repeatedly;
// caching avoids paginating the user's entire SSH key collection from the PDS
// on every single attempt. Errors are also cached (negative caching) with a
// shorter TTL so a failing PDS doesn't get hammered on every reconnect.
func (srv *server) cachedGetSSHPublicKeys(ctx context.Context, pdsUrl, did string) ([]*SSHPublicKey, error) {
	srv.sshPublicKeyCacheMu.RLock()
	if entry, ok := srv.sshPublicKeyCache[did]; ok && time.Now().Before(entry.expiresAt) {
		keys, err := entry.keys, entry.err
		srv.sshPublicKeyCacheMu.RUnlock()
		return keys, err
	}
	srv.sshPublicKeyCacheMu.RUnlock()

	keys, err := getSSHPublicKeys(ctx, pdsUrl, did)

	srv.sshPublicKeyCacheMu.Lock()
	ttl := sshPublicKeyCacheTTL
	if err != nil {
		ttl = sshPublicKeyNegCacheTTL
	}
	srv.sshPublicKeyCache[did] = &sshPublicKeyCacheEntry{
		keys:      keys,
		err:       err,
		expiresAt: time.Now().Add(ttl),
	}
	srv.sshPublicKeyCacheMu.Unlock()

	return keys, err
}

func getSSHPublicKeys(ctx context.Context, pdsUrl, did string) ([]*SSHPublicKey, error) {
	pds := &xrpc.Client{Host: pdsUrl} // or the user's PDS endpoint
	collection := "com.fedproxy.sshPublicKey"

	sshPublicKeys := make([]*SSHPublicKey, 0)

	const limit int64 = 100
	cursor := ""

	for {
		// last arg is reverse (oldest first)
		out, err := agnostic.RepoListRecords(ctx, pds, collection, cursor, limit, did, false)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("error calling RepoListRecords(pds=%s, did=%s)", pds, did))
		}

		for _, rec := range out.Records {
			if rec == nil {
				continue
			}

			var sshPublicKey SSHPublicKey

			err := sshPublicKey.ATProtoDecode(rec)
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("error unmarshaling json value of type sshPublicKey(pds=%s, did=%s, uri=%s)", pds, did, rec.Uri))
			}

			sshPublicKeys = append(sshPublicKeys, &sshPublicKey)
		}

		if out.Cursor == nil || *out.Cursor == "" {
			break
		}
		cursor = *out.Cursor
	}

	return sshPublicKeys, nil
}
