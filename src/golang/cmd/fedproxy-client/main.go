// fedproxy-client: registers an SSH public key via ATProto createRecord
// then holds an SSH remote-forward tunnel.
//
// Auth plugin selected by AUTH_PLUGIN env var:
//
//	oidc         (default) – exchanges an OIDC ID-token at a custom issuer
//	app-password – calls com.atproto.server.createSession with an app-password
//
// Required env vars (both plugins):
//
//	ATPRP_URL   – reverse-proxy base URL, e.g. https://rp.fedproxy.com
//
// Optional when MARKET_ACCEPT_JSON_PATH is set (derived from accept.uri):
//
//	HANDLE      – ATProto handle, e.g. johnandersen777.bsky.social   (resolved from DID if unset)
//	DID_PLC     – full DID,          e.g. did:plc:5svqtrhheairglgiiyvutzik (extracted from accept.uri if unset)
//
// OIDC plugin — all config read from accept.json (MARKET_ACCEPT_JSON_PATH required):
//
//	bid_config.value.url_path   → file containing OIDC issuer base URL
//	bid_config.value.url_route  → OIDC issue route  (default: /v1/oidc/issue)
//	bid_config.value.token_path → file containing OIDC ID token
//	bid_config.value.actx_path  → file containing team UUID
//	vm.value.role               → role name          (default: my-cool-role)
//
// App-password plugin env vars:
//
//	ATPROTO_HANDLE       – handle to log in as (default: $HANDLE); PDS resolved via identity
//	ATPROTO_APP_PASSWORD – app-password
//
// Tunnel env vars:
//
//	SSH_HOST     – SSH server host (default: fedproxy.com)
//	SSH_PORT     – SSH server port (default: 2222)
//	SSH_KEY_PATH – path to ed25519 private key (default: ~/.ssh/id_ed25519)
//	LOCAL_ADDR   – local TCP address to forward (default: 127.0.0.1:8080)
//	SERVICE      – service name / subdomain (generated randomly if unset)
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// ---------------------------------------------------------------------------
// JSON structured logger → stderr
// ---------------------------------------------------------------------------

func logJSON(level string, msg string, fields map[string]any) {
	entry := map[string]any{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}
	data, _ := json.Marshal(entry)
	data = append(data, '\n')
	os.Stderr.Write(data) //nolint:errcheck
}

func logInfo(msg string, fields map[string]any)  { logJSON("info", msg, fields) }
func logError(msg string, fields map[string]any) { logJSON("error", msg, fields) }
func logFatal(msg string, fields map[string]any) {
	logJSON("fatal", msg, fields)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// Logging HTTP RoundTripper — pre-request log + failure body/headers
// ---------------------------------------------------------------------------

type loggingTransport struct {
	wrapped http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	logInfo("http request", map[string]any{
		"method": req.Method,
		"url":    req.URL.String(),
	})

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		logError("http request failed", map[string]any{
			"method": req.Method,
			"url":    req.URL.String(),
			"error":  err.Error(),
		})
		return resp, err
	}

	if resp.StatusCode >= 400 {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))

		headers := map[string]string{}
		for k, vs := range resp.Header {
			headers[k] = strings.Join(vs, ", ")
		}

		fields := map[string]any{
			"method":  req.Method,
			"url":     req.URL.String(),
			"status":  resp.StatusCode,
			"headers": headers,
			"body":    string(body),
		}
		if readErr != nil {
			fields["body_read_err"] = readErr.Error()
		}
		logError("http response error", fields)
	}

	return resp, nil
}

func newLoggingHTTPClient() *http.Client {
	return &http.Client{
		Transport: &loggingTransport{wrapped: http.DefaultTransport},
	}
}

// ---------------------------------------------------------------------------
// accept.json  (com.publicdomainrelay.temp.market.accept)
// ---------------------------------------------------------------------------

type AcceptJSON struct {
	Bid struct {
		URI string `json:"uri"`
	} `json:"bid"`
	BidConfig struct {
		Value struct {
			URLPath   string `json:"url_path"`
			URLRoute  string `json:"url_route"`
			TokenPath string `json:"token_path"`
			ActxPath  string `json:"actx_path"`
			Subject   string `json:"subject"`
		} `json:"value"`
	} `json:"bid_config"`
	VM struct {
		Value struct {
			Role string `json:"role"`
		} `json:"value"`
	} `json:"vm"`
}

func (a *AcceptJSON) DID() (string, error) {
	rest := strings.TrimPrefix(a.Bid.URI, "at://")
	if rest == a.Bid.URI {
		return "", fmt.Errorf("bid.uri is not an AT-URI: %s", a.Bid.URI)
	}
	did := strings.SplitN(rest, "/", 2)[0]
	if did == "" {
		return "", fmt.Errorf("could not extract DID from bid.uri: %s", a.Bid.URI)
	}
	return did, nil
}

func loadAcceptJSON(path string) (*AcceptJSON, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "read accept.json %s", path)
	}
	var a AcceptJSON
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, errors.Wrap(err, "parse accept.json")
	}
	return &a, nil
}

// ---------------------------------------------------------------------------
// Token plugin interface
// ---------------------------------------------------------------------------

type TokenPlugin interface {
	GetToken(ctx context.Context, didPLC string) (string, error)
}

// ---------------------------------------------------------------------------
// OIDC plugin
// ---------------------------------------------------------------------------

type OIDCPlugin struct {
	BaseURL         string
	TeamUUID        string
	IDToken         string
	Role            string
	URLRoute        string
	SubjectTemplate string
	httpClient      *http.Client
}

func newOIDCPlugin(accept *AcceptJSON) (*OIDCPlugin, error) {
	if accept == nil {
		return nil, fmt.Errorf("oidc plugin requires MARKET_ACCEPT_JSON_PATH")
	}
	p := &OIDCPlugin{httpClient: newLoggingHTTPClient()}

	p.Role = accept.VM.Value.Role
	if p.Role == "" {
		p.Role = "my-cool-role"
	}

	p.URLRoute = accept.BidConfig.Value.URLRoute
	if p.URLRoute == "" {
		p.URLRoute = "/v1/oidc/issue"
	}

	p.SubjectTemplate = accept.BidConfig.Value.Subject

	if accept.BidConfig.Value.URLPath == "" {
		return nil, fmt.Errorf("accept.json bid_config.value.url_path must be set")
	}
	data, err := os.ReadFile(accept.BidConfig.Value.URLPath)
	if err != nil {
		return nil, errors.Wrapf(err, "read OIDC base URL from url_path=%s", accept.BidConfig.Value.URLPath)
	}
	p.BaseURL = strings.TrimSpace(string(data))

	if accept.BidConfig.Value.TokenPath == "" {
		return nil, fmt.Errorf("accept.json bid_config.value.token_path must be set")
	}
	if data, err = os.ReadFile(accept.BidConfig.Value.TokenPath); err != nil {
		return nil, errors.Wrapf(err, "read OIDC ID token from token_path=%s", accept.BidConfig.Value.TokenPath)
	}
	p.IDToken = strings.TrimSpace(string(data))

	if accept.BidConfig.Value.ActxPath == "" {
		return nil, fmt.Errorf("accept.json bid_config.value.actx_path must be set")
	}
	if data, err = os.ReadFile(accept.BidConfig.Value.ActxPath); err != nil {
		return nil, errors.Wrapf(err, "read team UUID from actx_path=%s", accept.BidConfig.Value.ActxPath)
	}
	p.TeamUUID = strings.TrimSpace(string(data))

	return p, nil
}

func (p *OIDCPlugin) GetToken(ctx context.Context, didPLC string) (string, error) {
	didPLCKey := strings.TrimPrefix(didPLC, "did:plc:")
	subjectTmpl := p.SubjectTemplate
	if subjectTmpl == "" {
		subjectTmpl = "actx:{actx}:plc:{did-plc-key}:role:{role}"
	}
	subject := strings.NewReplacer(
		"{actx}", p.TeamUUID,
		"{did-plc-key}", didPLCKey,
		"{role}", p.Role,
	).Replace(subjectTmpl)
	aud := fmt.Sprintf("api://ATProto?actx=%s", didPLC)

	payload, err := json.Marshal(map[string]any{
		"aud": aud,
		"sub": subject,
		"ttl": 3600,
	})
	if err != nil {
		return "", errors.Wrap(err, "marshal oidc request")
	}

	issueURL := strings.TrimRight(p.BaseURL, "/") + p.URLRoute
	req, err := http.NewRequestWithContext(ctx, "POST", issueURL, bytes.NewReader(payload))
	if err != nil {
		return "", errors.Wrap(err, "build oidc request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(p.IDToken))

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "oidc issue request")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc issue status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", errors.Wrap(err, "decode oidc response")
	}
	if result.Token == "" {
		return "", fmt.Errorf("oidc response missing token field: %s", body)
	}
	return result.Token, nil
}

// ---------------------------------------------------------------------------
// App-password plugin
// ---------------------------------------------------------------------------

type AppPasswordPlugin struct {
	Handle      string
	AppPassword string
}

func newAppPasswordPlugin() (*AppPasswordPlugin, error) {
	p := &AppPasswordPlugin{
		Handle:      envOrDefault("ATPROTO_HANDLE", os.Getenv("HANDLE")),
		AppPassword: os.Getenv("ATPROTO_APP_PASSWORD"),
	}
	if p.Handle == "" {
		return nil, fmt.Errorf("ATPROTO_HANDLE (or HANDLE) must be set")
	}
	if p.AppPassword == "" {
		return nil, fmt.Errorf("ATPROTO_APP_PASSWORD must be set")
	}
	return p, nil
}

func (p *AppPasswordPlugin) GetToken(ctx context.Context, _ string) (string, error) {
	ident, err := resolveIdentity(ctx, p.Handle)
	if err != nil {
		return "", errors.Wrap(err, "resolve identity")
	}
	pdsURL := ident.PDSEndpoint()
	if pdsURL == "" {
		return "", fmt.Errorf("no PDS endpoint in DID document for %s", p.Handle)
	}
	logInfo("resolved PDS", map[string]any{"pds": pdsURL, "handle": p.Handle})

	pdsClient := &xrpc.Client{
		Host:   pdsURL,
		Client: newLoggingHTTPClient(),
	}
	out, err := atproto.ServerCreateSession(ctx, pdsClient, &atproto.ServerCreateSession_Input{
		Identifier: p.Handle,
		Password:   p.AppPassword,
	})
	if err != nil {
		return "", errors.Wrap(err, "createSession")
	}
	return out.AccessJwt, nil
}

// ---------------------------------------------------------------------------
// Identity resolution via indigo
// ---------------------------------------------------------------------------

func resolveIdentity(ctx context.Context, handleOrDID string) (*identity.Identity, error) {
	atid, err := syntax.ParseAtIdentifier(handleOrDID)
	if err != nil {
		return nil, errors.Wrap(err, "parse at-identifier")
	}
	dir := identity.DefaultDirectory()
	ident, err := dir.Lookup(ctx, atid)
	if err != nil {
		return nil, errors.Wrapf(err, "identity lookup %s", handleOrDID)
	}
	return ident, nil
}

// ---------------------------------------------------------------------------
// SSH key helpers
// ---------------------------------------------------------------------------

func ensureSSHKey(keyPath string) (ssh.Signer, string, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return nil, "", errors.Wrap(err, "mkdir .ssh")
	}

	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, "", errors.Wrap(err, "parse existing key")
			}
			signer, err := ssh.NewSignerFromKey(raw)
			if err != nil {
				return nil, "", errors.Wrap(err, "signer from existing key")
			}
			pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
			return signer, pubStr, nil
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", errors.Wrap(err, "generate ed25519 key")
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", errors.Wrap(err, "marshal private key")
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		return nil, "", errors.Wrap(err, "write private key")
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, "", errors.Wrap(err, "ssh public key")
	}
	pubStr := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if err := os.WriteFile(keyPath+".pub", []byte(pubStr+"\n"), 0644); err != nil {
		return nil, "", errors.Wrap(err, "write public key")
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", errors.Wrap(err, "signer from new key")
	}
	return signer, pubStr, nil
}

// ---------------------------------------------------------------------------
// createRecord via xrpc
// ---------------------------------------------------------------------------

func createRecord(ctx context.Context, atprpURL, token, didPLC, service, sshPub string) error {
	client := &xrpc.Client{
		Host:   atprpURL,
		Auth:   &xrpc.AuthInfo{AccessJwt: token},
		Client: newLoggingHTTPClient(),
	}

	input := map[string]any{
		"repo":       didPLC,
		"collection": "com.fedproxy.sshPublicKey",
		"record": map[string]any{
			"$type":     "com.fedproxy.sshPublicKey",
			"key":       sshPub,
			"service":   service,
			"name":      service,
			"createdAt": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		},
	}

	logInfo("createRecord", map[string]any{
		"url":        atprpURL,
		"did":        didPLC,
		"service":    service,
		"collection": "com.fedproxy.sshPublicKey",
	})

	var out atproto.RepoCreateRecord_Output
	if err := client.LexDo(ctx, lexutil.Procedure, "application/json",
		"com.atproto.repo.createRecord", nil, input, &out); err != nil {
		return errors.Wrap(err, "createRecord")
	}
	logInfo("createRecord ok", map[string]any{"uri": out.Uri, "cid": out.Cid})
	return nil
}

// ---------------------------------------------------------------------------
// SSH tunnel
// ---------------------------------------------------------------------------

func runTunnel(ctx context.Context, signer ssh.Signer, sshHost, sshPort, handle, service, localAddr string) error {
	config := &ssh.ClientConfig{
		User:            handle,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(sshHost, sshPort)
	logInfo("ssh connect", map[string]any{"addr": addr, "user": handle})
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return errors.Wrap(err, "ssh dial")
	}
	defer client.Close()

	remoteAddr := fmt.Sprintf("%s:80", service)
	ln, err := client.Listen("tcp", remoteAddr)
	if err != nil {
		return errors.Wrapf(err, "ssh remote listen %s", remoteAddr)
	}
	defer ln.Close()

	logInfo("tunnel active", map[string]any{"remote": remoteAddr, "local": localAddr})

	go func() {
		<-ctx.Done()
		ln.Close()
		client.Close()
	}()

	for {
		remote, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return errors.Wrap(err, "tunnel accept")
			}
		}
		go forward(remote, localAddr)
	}
}

func forward(remote net.Conn, localAddr string) {
	defer remote.Close()
	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		logError("forward dial", map[string]any{"addr": localAddr, "error": err.Error()})
		return
	}
	defer local.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(local, remote); done <- struct{}{} }() //nolint:errcheck
	go func() { io.Copy(remote, local); done <- struct{}{} }() //nolint:errcheck
	<-done
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrFile(envKey, pathKey string) (string, error) {
	if v := os.Getenv(envKey); v != "" {
		return strings.TrimSpace(v), nil
	}
	if p := os.Getenv(pathKey); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", errors.Wrapf(err, "read %s", p)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return "", fmt.Errorf("%s or %s must be set", envKey, pathKey)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	atprpURL := os.Getenv("ATPRP_URL")
	if atprpURL == "" {
		logFatal("ATPRP_URL must be set", nil)
	}

	var accept *AcceptJSON
	if p := os.Getenv("MARKET_ACCEPT_JSON_PATH"); p != "" {
		var err error
		if accept, err = loadAcceptJSON(p); err != nil {
			logFatal("load accept.json", map[string]any{"error": err.Error()})
		}
		logInfo("loaded accept.json", map[string]any{"path": p})
	}

	didPLC := os.Getenv("DID_PLC")
	if didPLC == "" && accept != nil {
		var err error
		if didPLC, err = accept.DID(); err != nil {
			logFatal("extract DID from accept.json", map[string]any{"error": err.Error()})
		}
		logInfo("DID from accept.json", map[string]any{"did": didPLC})
	}
	if didPLC == "" {
		logFatal("DID_PLC must be set (or provide MARKET_ACCEPT_JSON_PATH)", nil)
	}

	handle := os.Getenv("HANDLE")
	if handle == "" {
		ident, err := resolveIdentity(ctx, didPLC)
		if err != nil {
			logFatal("resolve handle from DID", map[string]any{"did": didPLC, "error": err.Error()})
		}
		handle = ident.Handle.String()
		logInfo("handle resolved from DID", map[string]any{"handle": handle})
	}

	service := os.Getenv("SERVICE")
	if service == "" {
		service = randomHex(4)
	}

	sshHost := envOrDefault("SSH_HOST", "fedproxy.com")
	sshPort := envOrDefault("SSH_PORT", "2222")
	localAddr := envOrDefault("LOCAL_ADDR", "127.0.0.1:8080")
	keyPath := envOrDefault("SSH_KEY_PATH", filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"))

	pluginName := envOrDefault("AUTH_PLUGIN", "oidc")
	var plugin TokenPlugin
	switch pluginName {
	case "oidc":
		p, err := newOIDCPlugin(accept)
		if err != nil {
			logFatal("oidc plugin", map[string]any{"error": err.Error()})
		}
		plugin = p
	case "app-password":
		p, err := newAppPasswordPlugin()
		if err != nil {
			logFatal("app-password plugin", map[string]any{"error": err.Error()})
		}
		plugin = p
	default:
		logFatal("unknown AUTH_PLUGIN", map[string]any{"plugin": pluginName, "valid": "oidc,app-password"})
	}

	signer, sshPub, err := ensureSSHKey(keyPath)
	if err != nil {
		logFatal("ssh key", map[string]any{"error": err.Error()})
	}
	logInfo("ssh key ready", map[string]any{"public_key": sshPub})

	logInfo("getting token", map[string]any{"plugin": pluginName, "did": didPLC})
	token, err := plugin.GetToken(ctx, didPLC)
	if err != nil {
		logFatal("get token", map[string]any{"plugin": pluginName, "error": err.Error()})
	}
	logInfo("token obtained", map[string]any{"plugin": pluginName})

	if err := createRecord(ctx, atprpURL, token, didPLC, service, sshPub); err != nil {
		logFatal("createRecord", map[string]any{"error": err.Error()})
	}
	logInfo("registered", map[string]any{"service": service, "handle": handle})

	for {
		if err := runTunnel(ctx, signer, sshHost, sshPort, handle, service, localAddr); err != nil {
			logError("tunnel dropped", map[string]any{"error": err.Error(), "retry_in": "1s"})
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
