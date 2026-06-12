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
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// reg tracks every forward currently established so the reconcile loop can
// re-push its Caddy routes if Caddy is restarted out from under us (e.g. by a
// deploy), which wipes all dynamically-pushed config. Keyed by
// serviceName + "\x00" + userHandle (the same identity a route @id derives from).
var (
	regMu sync.Mutex
	reg   = map[string]*forward{}
)

func forwardKey(f *forward) string { return f.serviceName + "\x00" + f.userHandle }

func main() {
	log.Println("▶️ Starting SSH-forward server")

	signer, err := loadOrGenerateHostKey("host_key")
	if err != nil {
		log.Fatalf("❌ host key load/generate failed: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			ctx := context.Background()

			// Check if we have a valid ATProto handle as SSH username
			log.Printf("Resolving DID PLC and PDS for user=%s", c.User())
			ident, err := resolveATProtoIdentifier(ctx, c.User())
			if err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("Failed to resolve DID PLC and PDS for user=%s: %v", c.User()))
			}
			pds := ident.PDSEndpoint()
			if pds == "" {
				return nil, errors.Wrap(err, fmt.Sprintf("Could not find PDS for user=%s", c.User()))
			}
			log.Printf("Got DID PLC and PDS for user=%s did=%s pds=%s", c.User(), ident.DID, pds)

			log.Printf("Resolving public keys for user=%s", c.User())
			sshPublicKeys, err := getSSHPublicKeys(ctx, pds, ident.DID.String())
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
					// Record the public key used for authentication.
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

	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("❌ listen tcp: %v", err)
	}
	log.Println("✅ SSH listening on :2222")

	// Install the wildcard DNS-01 on_demand policy + catch-all immediately and
	// keep them (plus every active forward's route) alive. Without this the
	// DNS-01 policy only existed after the first forward connected, and any
	// Caddy restart silently dropped all dynamic config until clients happened
	// to reconnect — leaving on-demand cert issuance dead in the meantime.
	if caddySock := os.Getenv("CADDY_SOCK"); caddySock != "" {
		go reconcileLoop(getCaddyClient(caddySock))
		log.Println("♻️ started Caddy reconcile loop")
	} else {
		log.Println("⚠️ CADDY_SOCK unset — Caddy reconciliation disabled")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("⚠️ accept error: %v", err)
			continue
		}
		go handleSSH(conn, cfg)
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

func handleSSH(raw net.Conn, cfg *ssh.ServerConfig) {
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
			err = configureNewForward(ctx, f)
			if err != nil {
				log.Printf("❌ failed to setup caddy forward for %s: %v", p.BindAddr, err)
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
				err := unconfigureForward(ctx, f)
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
		err := unconfigureForward(ctx, f)
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

	go func() {
		io.Copy(channel, conn)
		channel.CloseWrite()
	}()
	io.Copy(conn, channel)
	channel.Close()
	log.Printf("✅ closed TCP proxy for %s:%d", f.BindAddr, f.BindPort)
}

// getCaddyClient is a helper to build an HTTP client that communicates over a Unix socket
func getCaddyClient(caddySockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", caddySockPath)
			},
		},
	}
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
func ensureSrv0Exists(ctx context.Context, client *http.Client) error {
	checkReq, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/config/apps/http/servers/srv0", nil)
	resp, err := client.Do(checkReq)
	if err == nil {
		defer resp.Body.Close()
		log.Printf("caddy check srv0 resp.StatusCode=%s", resp.StatusCode)
		if resp.StatusCode == http.StatusOK {
			// Disable idle_timeout so WebSocket connections are never
			// idle-closed by Caddy (Caddy ignores WS ping frames as activity).
			// "0" means disabled; dead peers are caught at the TCP level.
			// Only PATCH when it isn't already "0": every write reloads Caddy's
			// config and cancels in-flight ACME orders, so an unconditional
			// per-tick PATCH would starve HTTP-01 issuance. Parsing the srv0 we
			// just fetched keeps the steady-state path GET-only.
			var srv struct {
				IdleTimeout json.RawMessage `json:"idle_timeout"`
			}
			body, _ := io.ReadAll(resp.Body)
			_ = json.Unmarshal(body, &srv)
			// Caddy serializes a 0 caddy.Duration as omitempty, so a disabled
			// idle_timeout returns as an absent key (nil RawMessage) or JSON
			// null — both mean "already disabled". Treat them like "0" and skip
			// the PATCH; PATCHing an absent key 404s every tick otherwise.
			idle := string(srv.IdleTimeout)
			if idle != `"0"` && idle != "0" && idle != "" && idle != "null" {
				patchBody, _ := json.Marshal("0")
				patchReq, _ := http.NewRequestWithContext(ctx, "PATCH",
					"http://127.0.0.1/config/apps/http/servers/srv0/idle_timeout",
					bytes.NewReader(patchBody))
				patchReq.Header.Set("Content-Type", "application/json")
				if pr, err := client.Do(patchReq); err != nil {
					log.Printf("❌ idle_timeout PATCH failed: %v — WS connections may drop on idle", err)
				} else {
					if pr.StatusCode >= 300 {
						body, _ := io.ReadAll(pr.Body)
						log.Printf("❌ idle_timeout PATCH non-success %d: %s — WS connections may drop on idle", pr.StatusCode, string(body))
					}
					pr.Body.Close()
				}
			}
			return ensureWildcardTLSPolicy(ctx, client)
		}
	}
	log.Println("caddy creating srv0...")

	// idle_timeout "0" disables the HTTP idle timer entirely.
	// Caddy does not recognize WS ping frames as activity, so any non-zero
	// timeout would kill silent-but-alive WebSocket sessions. Dead peers are
	// caught at the TCP level via OS keepalives.
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

	// Fast path: policy already present, nothing to write.
	if idExists(ctx, client, policyID) {
		return nil
	}

	// One DNS-01 (Cloudflare) automation policy, subject-less so it's Caddy's
	// default issuer. on_demand stays enabled as a FALLBACK — gated by
	// on_demand_tls.ask — for names not covered by the shared wildcard, e.g. an
	// explicit "*.service" child wildcard. Normal flattened hosts never reach
	// on_demand: the shared "*.<endpoint>" wildcard cert (automated just below)
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

	// Proactively manage the ONE shared wildcard cert so every flattened
	// svc--handle host is served from it (no per-name ACME).
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

// flattenLabel folds an identity part that may contain dots (a handle like
// "alice.bsky.social", or a dotted service name) into a single DNS label by
// replacing each dot with a dash.
func flattenLabel(s string) string { return strings.ReplaceAll(s, ".", "-") }

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

func configureNewForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}
	caddySockPath := os.Getenv("CADDY_SOCK")
	if caddySockPath == "" {
		return fmt.Errorf("CADDY_SOCK must be set")
	}
	client := getCaddyClient(caddySockPath)

	// Ensure srv0 + the wildcard DNS-01 policy + catch-all exist before
	// posting routes (avoids a 404 on the routes array, and guarantees the
	// on_demand policy the cert gate depends on is present).
	if err := ensureSrv0Exists(ctx, client); err != nil {
		return errors.Wrap(err, "failed to ensure srv0 existence")
	}

	// Reject forwards whose flattened "<service>--<handle>" label would exceed
	// the DNS 63-char label limit — it'd be an invalid, unroutable hostname.
	svc := strings.TrimPrefix(f.serviceName, "*.")
	if label := serviceLabel(svc, f.userHandle); len(label) > 63 {
		return fmt.Errorf("flattened service label %q is %d chars, over the 63-char DNS label limit (service=%q handle=%q)", label, len(label), f.serviceName, f.userHandle)
	}

	for _, fqdn := range forwardFQDNs(f, thisEndpoint) {
		if err := ensureForwardRoute(ctx, client, fqdn, f.localPath); err != nil {
			return errors.Wrap(err, fmt.Sprintf("error configuring caddy for fqdn=%s", fqdn))
		}
		// Normal flattened hosts ride the shared "*.<endpoint>" wildcard cert,
		// so they need no issuance. An explicit "*.service" child wildcard is
		// two labels deep and NOT covered by it, so mint its own DNS-01 cert.
		if strings.HasPrefix(fqdn, "*.") {
			triggerCertIssuance(ctx, client, fqdn)
		}
	}

	// Record the forward so the reconcile loop re-pushes its routes if Caddy
	// is restarted and loses them.
	regMu.Lock()
	reg[forwardKey(f)] = f
	regMu.Unlock()

	// Re-append catch-all AFTER the new forward route so it stays last.
	if err := ensureCatchAllRoute(ctx, client); err != nil {
		return errors.Wrap(err, "ensure catch-all route after forward")
	}
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

// triggerCertIssuance best-effort adds the name to the managed-cert list so
// DNS-01 issuance starts immediately rather than on the first handshake. Used
// for the shared "*.<endpoint>" wildcard and for explicit "*.service" child
// wildcards (which on_demand cannot mint). Best-effort: errors non-fatal.
func triggerCertIssuance(ctx context.Context, client *http.Client, fqdn string) {
	body, err := json.Marshal([]string{fqdn})
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		"http://127.0.0.1/config/apps/tls/certificates/automate", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r, err := client.Do(req); err == nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		log.Printf("🔐 triggered background cert issuance for %s", fqdn)
	}
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
func reconcileLoop(client *http.Client) {
	const interval = 30 * time.Second
	for {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			defer cancel()

			if err := ensureSrv0Exists(ctx, client); err != nil {
				log.Printf("⚠️ reconcile base config: %v", err)
				return
			}

			thisEndpoint := os.Getenv("THIS_ENDPOINT")
			regMu.Lock()
			fwds := make([]*forward, 0, len(reg))
			for _, f := range reg {
				fwds = append(fwds, f)
			}
			regMu.Unlock()

			appended := false
			for _, f := range fwds {
				for _, fqdn := range forwardFQDNs(f, thisEndpoint) {
					if idExists(ctx, client, "route-"+fqdn) {
						continue
					}
					if err := ensureForwardRoute(ctx, client, fqdn, f.localPath); err != nil {
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
			if appended || !idExists(ctx, client, catchAllID) {
				if err := ensureCatchAllRoute(ctx, client); err != nil {
					log.Printf("⚠️ reconcile catch-all route: %v", err)
				}
			}
		}()
		time.Sleep(interval)
	}
}

func unconfigureForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}

	// Stop reconciling this forward before tearing its routes down, so the
	// loop doesn't race to re-add what we're removing.
	regMu.Lock()
	if reg[forwardKey(f)] == f {
		delete(reg, forwardKey(f))
	}
	regMu.Unlock()

	fqdns := forwardFQDNs(f, thisEndpoint)
	for _, fqdn := range fqdns {
		routeID := "route-" + fqdn

		caddySockPath := os.Getenv("CADDY_SOCK")
		if caddySockPath == "" {
			return fmt.Errorf("CADDY_SOCK must be set")
		}

		client := getCaddyClient(caddySockPath)

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

func resolveATProtoIdentifier(ctx context.Context, inputId string) (*identity.Identity, error) {
	id, err := syntax.ParseAtIdentifier(inputId)
	if err != nil {
		return nil, err
	}
	slog.Info("valid syntax", "at-identifier", id)

	// https://github.com/bluesky-social/indigo/blob/ce62b8fce9e01434213a69cb251852b2c9436cb9/atproto/identity/directory.go#L65
	// DefaultDirectory is https://plc.directory
	dir := identity.DefaultDirectory()
	ident, err := dir.Lookup(ctx, id)
	if err != nil {
		return nil, err
	}

	return ident, nil
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
			fmt.Printf("uri=%s cid=%s value=%s\n", rec.Uri, rec.Cid, rec.Value)

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
