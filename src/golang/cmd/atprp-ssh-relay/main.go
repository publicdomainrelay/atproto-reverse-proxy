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

			for _, sshPublicKey := range sshPublicKeys {
				authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshPublicKey.Key))
				if err != nil {
					log.Printf("error parsing ssh public key for user=%s key=%s: %v", c.User(), sshPublicKey.Key, err)
					continue
				}

				if string(authorizedKey.Marshal()) == string(pubKey.Marshal()) {
					return &ssh.Permissions{
						// Record the public key used for authentication.
						Extensions: map[string]string{
							"pubkey-fp":                ssh.FingerprintSHA256(pubKey),
							"pubkey-valid-for-service": sshPublicKey.Service,
						},
					}, nil
				}
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

			listener, err := net.Listen("unix", localPath)
			if err != nil {
				log.Printf("❌ failed to listen on %s: %v", localPath, err)
				req.Reply(false, nil)
				continue
			}

			mu.Lock()
			forwards[base] = &forward{listener, localPath, fmt.Sprintf("%s:%d", p.BindAddr, p.BindPort), serverConn.User()}
			mu.Unlock()

			req.Reply(true, nil)

			go acceptTCPLoop(ctx, listener, serverConn, &p)

			go notifyNewForward(ctx, &mu, forwards)

		case "cancel-tcpip-forward":
			var p TCPIPForward
			_ = ssh.Unmarshal(req.Payload, &p)
			base := "tcp.sock"
			log.Printf("📨 cancel-tcpip-forward request: %s:%d", p.BindAddr, p.BindPort)

			mu.Lock()
			if f, ok := forwards[base]; ok {
				f.listener.Close()
				delete(forwards, base)
				log.Printf("🗑 removed forward %s", base)
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

func notifyNewForward(ctx context.Context, mu *sync.Mutex, forwards map[string]*forward) {

	mu.Lock()
	data := make(map[string]string, len(forwards))
	for base, f := range forwards {
		data[base] = f.localPath
		data["service-name"] = f.serviceName
		data["handle"] = f.userHandle
	}
	mu.Unlock()

	log.Printf("data: %+v", data)

	control := os.Getenv("CONTROL_SOCK")
	if control == "" {
		return
	}

	body, _ := json.Marshal(data)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", control)
			},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://unix/connect/tmux", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ AGI POST error: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("✅ AGI POST success: %d forwards sent: %v", len(data), data)
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
