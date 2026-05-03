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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
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

	cfg := &ssh.ServerConfig{NoClientAuth: true}
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
