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
			mu.Lock()
			err = configureNewForward(ctx, f)
			mu.Unlock()
			if err != nil {
				log.Printf("❌ failed to setup caddy forward for %s: %v", p.BindAddr, err)
				req.Reply(false, nil)
				continue
			}
			forwards[p.BindAddr] = f

			req.Reply(true, nil)

			go acceptTCPLoop(ctx, listener, serverConn, &p)

		case "cancel-tcpip-forward":
			var p TCPIPForward
			_ = ssh.Unmarshal(req.Payload, &p)
			log.Printf("📨 cancel-tcpip-forward request: %s:%d", p.BindAddr, p.BindPort)

			mu.Lock()
			if f, ok := forwards[p.BindAddr]; ok {
				f.listener.Close()
				unconfigureForward(ctx, f)
				delete(forwards, p.BindAddr)
				log.Printf("🗑 removed forward %s", p.BindAddr)
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
	log.Println("🔒 SSH session closed, cleaning up")

	// TODO Remove from Caddy
	// TODO Range over forwards
	//			if f, ok := forwards[p.BindAddr]; ok {
	//				f.listener.Close()
	//				unconfigureForward(ctx, f)
	//				delete(forwards, p.BindAddr)
	//				log.Printf("🗑 removed forward %s", p.BindAddr)
	//			}
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
		OriginAddr: f.BindAddr,
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
func ensureSrv0Exists(ctx context.Context, client *http.Client) error {
	checkReq, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/config/apps/http/servers/srv0", nil)
	resp, err := client.Do(checkReq)
	if err == nil {
		defer resp.Body.Close()
		log.Printf("caddy check srv0 resp.StatusCode=%s", resp.StatusCode)
		if resp.StatusCode == http.StatusOK {
			return nil
		}
	}
	log.Println("caddy creating srv0...")

	// Initialize the standard server structure if srv0 is missing
	srvPayload := map[string]any{
		"listen": []string{":443"}, // e.g. ":443" or a unix socket
		"routes": []any{},
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
	return nil
}

func configureNewForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}

	fqdn := fmt.Sprintf("%s.%s.%s", f.serviceName, f.userHandle, thisEndpoint)
	routeID := "route-" + fqdn
	forwardTo := f.localPath

	// Build the Caddy route JSON.
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
								"handler": "reverse_proxy",
								"upstreams": []map[string]any{
									{"dial": "unix/" + forwardTo},
								},
							},
						},
					},
				},
			},
		},
		"terminal": true,
	}

	caddySockPath := os.Getenv("CADDY_SOCK")
	if caddySockPath == "" {
		return fmt.Errorf("CADDY_SOCK must be set")
	}

	client := getCaddyClient(caddySockPath)

	// Ensure the server exists to avoid 404 when posting to the routes array
	if err := ensureSrv0Exists(ctx, client); err != nil {
		return errors.Wrap(err, "failed to ensure srv0 existence")
	}

	// 1. Remove the existing route first (if replacing/updating)
	deleteReq, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("http://127.0.0.1/id/%s", routeID), nil)
	if err != nil {
		return errors.Wrap(err, "failed to create delete request")
	}
	deleteResp, err := client.Do(deleteReq)
	if err == nil {
		io.Copy(io.Discard, deleteResp.Body)
		deleteResp.Body.Close()
	}

	// 2. Append the new route
	body, err := json.Marshal(routePayload)
	if err != nil {
		return errors.Wrap(err, "failed to marshal route payload")
	}

	reqPath := "http://127.0.0.1/config/apps/http/servers/srv0/routes"
	req, err := http.NewRequestWithContext(ctx, "POST", reqPath, bytes.NewReader(body))
	if err != nil {
		return errors.Wrap(err, "failed to create post request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("error configuring caddy for fqdn=%s", fqdn))
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned non-success status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func unconfigureForward(ctx context.Context, f *forward) error {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}

	fqdn := fmt.Sprintf("%s.%s.%s", f.serviceName, f.userHandle, thisEndpoint)
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
