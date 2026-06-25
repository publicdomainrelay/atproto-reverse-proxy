package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/api/agnostic"
	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"github.com/pkg/errors"
)

// ---------------------------------------------------------------------------
// Global state & context helpers
// ---------------------------------------------------------------------------

type GlobalState struct {
	ThisEndpoint     string
	ListenSocketPath string
	OAuthApp         *oauth.ClientApp
	Store            AppStore
}

type contextKey string

const globalStateKey contextKey = "com.fedproxy.app.web-ui.globalState"
const oauthSessionKey contextKey = "com.fedproxy.app.web-ui.oauthSession"

func GlobalStateFromContext(ctx context.Context) *GlobalState {
	if v := ctx.Value(globalStateKey); v != nil {
		if gs, ok := v.(*GlobalState); ok {
			return gs
		}
	}
	return nil
}

func OAuthSessionFromContext(ctx context.Context) *oauth.ClientSessionData {
	if v := ctx.Value(oauthSessionKey); v != nil {
		if s, ok := v.(*oauth.ClientSessionData); ok {
			return s
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// OAuth store — in-memory, SQLite, or PostgreSQL depending on DATABASE_URI
// ---------------------------------------------------------------------------

// AppStore extends ClientAuthStore with DID-based session lookup for cookie-less recovery.
type AppStore interface {
	oauth.ClientAuthStore
	GetSessionByDID(ctx context.Context, did syntax.DID) (*oauth.ClientSessionData, error)
}

// NewOAuthStore returns an AppStore backed by the DATABASE_URI env var.
// Schemes: postgres:// / postgresql:// → PostgreSQL via pgx; sqlite:// / sqlite3:// → SQLite;
// empty or unrecognised → in-memory.
func NewOAuthStore(ctx context.Context) (AppStore, error) {
	dbURI := os.Getenv("DATABASE_URI")
	if dbURI == "" {
		return newMemAppStore(), nil
	}
	u, err := url.Parse(dbURI)
	if err != nil {
		return nil, fmt.Errorf("invalid DATABASE_URI: %w", err)
	}
	switch u.Scheme {
	case "postgres", "postgresql":
		return newDBStore(ctx, "pgx", dbURI)
	case "sqlite", "sqlite3":
		// SQLAlchemy convention: sqlite:///relative, sqlite:////absolute
		path := strings.TrimPrefix(dbURI, u.Scheme+"://")
		path = strings.TrimPrefix(path, "/")
		return newDBStore(ctx, "sqlite", path)
	default:
		return newDBStore(ctx, "sqlite", dbURI)
	}
}

// ---- in-memory implementation ----

type memAppStore struct {
	mu       sync.Mutex
	sessions map[string]oauth.ClientSessionData // "did/sessionID" → data
	requests map[string]oauth.AuthRequestData   // state → data
	didOrder map[string][]string                // did → ordered sessionIDs (most recent last)
}

func newMemAppStore() *memAppStore {
	return &memAppStore{
		sessions: make(map[string]oauth.ClientSessionData),
		requests: make(map[string]oauth.AuthRequestData),
		didOrder: make(map[string][]string),
	}
}

func memKey(did syntax.DID, sessionID string) string {
	return did.String() + "/" + sessionID
}

func (m *memAppStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[memKey(did, sessionID)]
	if !ok {
		return nil, fmt.Errorf("session not found: %s/%s", did, sessionID)
	}
	return &s, nil
}

func (m *memAppStore) GetSessionByDID(ctx context.Context, did syntax.DID) (*oauth.ClientSessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := m.didOrder[did.String()]
	if len(ids) == 0 {
		return nil, fmt.Errorf("no session found for did: %s", did)
	}
	s, ok := m.sessions[memKey(did, ids[len(ids)-1])]
	if !ok {
		return nil, fmt.Errorf("no session found for did: %s", did)
	}
	return &s, nil
}

func (m *memAppStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(sess.AccountDID, sess.SessionID)
	if _, exists := m.sessions[k]; !exists {
		m.didOrder[sess.AccountDID.String()] = append(m.didOrder[sess.AccountDID.String()], sess.SessionID)
	}
	m.sessions[k] = sess
	return nil
}

func (m *memAppStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, memKey(did, sessionID))
	ids := m.didOrder[did.String()]
	for i, id := range ids {
		if id == sessionID {
			m.didOrder[did.String()] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	return nil
}

func (m *memAppStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.requests[state]
	if !ok {
		return nil, fmt.Errorf("auth request not found: %s", state)
	}
	return &r, nil
}

func (m *memAppStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.requests[info.State]; ok {
		return fmt.Errorf("auth request already saved for state %s", info.State)
	}
	m.requests[info.State] = info
	return nil
}

func (m *memAppStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.requests, state)
	return nil
}

// ---- database-backed implementation ----

// dbQueries holds pre-compiled SQL strings for a given driver dialect.
type dbQueries struct {
	getSession        string
	getSessionByDID   string
	saveSession       string
	deleteSession     string
	getAuthRequest    string
	saveAuthRequest   string
	deleteAuthRequest string
}

var sqliteQueries = dbQueries{
	getSession:      `SELECT data FROM atproto_oauth_sessions WHERE did = ? AND session_id = ?`,
	getSessionByDID: `SELECT data FROM atproto_oauth_sessions WHERE did = ? ORDER BY updated_at DESC LIMIT 1`,
	saveSession: `INSERT INTO atproto_oauth_sessions (did, session_id, data, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(did, session_id) DO UPDATE SET data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP`,
	deleteSession:     `DELETE FROM atproto_oauth_sessions WHERE did = ? AND session_id = ?`,
	getAuthRequest:    `SELECT data FROM atproto_oauth_auth_requests WHERE state = ?`,
	saveAuthRequest:   `INSERT INTO atproto_oauth_auth_requests (state, data) VALUES (?, ?)`,
	deleteAuthRequest: `DELETE FROM atproto_oauth_auth_requests WHERE state = ?`,
}

var pgxQueries = dbQueries{
	getSession:      `SELECT data FROM atproto_oauth_sessions WHERE did = $1 AND session_id = $2`,
	getSessionByDID: `SELECT data FROM atproto_oauth_sessions WHERE did = $1 ORDER BY updated_at DESC LIMIT 1`,
	saveSession: `INSERT INTO atproto_oauth_sessions (did, session_id, data, updated_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		ON CONFLICT(did, session_id) DO UPDATE SET data = EXCLUDED.data, updated_at = CURRENT_TIMESTAMP`,
	deleteSession:     `DELETE FROM atproto_oauth_sessions WHERE did = $1 AND session_id = $2`,
	getAuthRequest:    `SELECT data FROM atproto_oauth_auth_requests WHERE state = $1`,
	saveAuthRequest:   `INSERT INTO atproto_oauth_auth_requests (state, data) VALUES ($1, $2)`,
	deleteAuthRequest: `DELETE FROM atproto_oauth_auth_requests WHERE state = $1`,
}

type dbStore struct {
	db *sql.DB
	q  dbQueries
}

func newDBStore(ctx context.Context, driver, dsn string) (*dbStore, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db driver=%s: %w", driver, err)
	}
	q := sqliteQueries
	if driver == "pgx" {
		q = pgxQueries
	}
	s := &dbStore{db: db, q: q}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	return s, nil
}

func (s *dbStore) migrate(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS atproto_oauth_sessions (
			did TEXT NOT NULL,
			session_id TEXT NOT NULL,
			data TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (did, session_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_atproto_oauth_sessions_did ON atproto_oauth_sessions(did)`,
		`CREATE TABLE IF NOT EXISTS atproto_oauth_auth_requests (
			state TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *dbStore) GetSession(ctx context.Context, did syntax.DID, sessionID string) (*oauth.ClientSessionData, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, s.q.getSession, did.String(), sessionID).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found: %s/%s", did, sessionID)
		}
		return nil, err
	}
	var sess oauth.ClientSessionData
	return &sess, json.Unmarshal([]byte(raw), &sess)
}

func (s *dbStore) GetSessionByDID(ctx context.Context, did syntax.DID) (*oauth.ClientSessionData, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, s.q.getSessionByDID, did.String()).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no session found for did: %s", did)
		}
		return nil, err
	}
	var sess oauth.ClientSessionData
	return &sess, json.Unmarshal([]byte(raw), &sess)
}

func (s *dbStore) SaveSession(ctx context.Context, sess oauth.ClientSessionData) error {
	raw, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q.saveSession, sess.AccountDID.String(), sess.SessionID, string(raw))
	return err
}

func (s *dbStore) DeleteSession(ctx context.Context, did syntax.DID, sessionID string) error {
	_, err := s.db.ExecContext(ctx, s.q.deleteSession, did.String(), sessionID)
	return err
}

func (s *dbStore) GetAuthRequestInfo(ctx context.Context, state string) (*oauth.AuthRequestData, error) {
	var raw string
	if err := s.db.QueryRowContext(ctx, s.q.getAuthRequest, state).Scan(&raw); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("auth request not found: %s", state)
		}
		return nil, err
	}
	var info oauth.AuthRequestData
	return &info, json.Unmarshal([]byte(raw), &info)
}

func (s *dbStore) SaveAuthRequestInfo(ctx context.Context, info oauth.AuthRequestData) error {
	raw, err := json.Marshal(info)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, s.q.saveAuthRequest, info.State, string(raw))
	return err
}

func (s *dbStore) DeleteAuthRequestInfo(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, s.q.deleteAuthRequest, state)
	return err
}

// ---------------------------------------------------------------------------
// oauthRoundTripper — wraps a ClientSession as an http.RoundTripper so the
// reverse proxy can forward requests with DPoP auth and automatic token refresh.
// ---------------------------------------------------------------------------

type oauthRoundTripper struct {
	sess *oauth.ClientSession
}

func (t *oauthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// http.Client.Do (called inside DoWithAuth) rejects requests with
	// RequestURI set; httputil.ReverseProxy fills it in, so clear it here.
	req.RequestURI = ""

	// DoWithAuth may retry the request (DPoP nonce update, token refresh) and
	// needs to re-read the body. ReverseProxy's wrapped body is closed after
	// the first read, and outreq.GetBody is not always set, so buffer the body
	// here and provide a GetBody that yields fresh readers on retry.
	if req.Body != nil && req.GetBody == nil {
		buf, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("buffer request body: %w", err)
		}
		req.Body = io.NopCloser(strings.NewReader(string(buf)))
		req.ContentLength = int64(len(buf))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(string(buf))), nil
		}
	}

	return t.sess.DoWithAuth(http.DefaultClient, req, syntax.NSID(""))
}

func main() {
	ctx := context.Background()
	if err := realMain(ctx); err != nil {
		log.Fatalf("app=%s failed: %v", globalStateKey, err)
	}
}

func NewGlobalState(ctx context.Context) (*GlobalState, error) {
	thisEndpoint := os.Getenv("THIS_ENDPOINT")
	if thisEndpoint == "" {
		return nil, fmt.Errorf("THIS_ENDPOINT must be set to root FQDN")
	}
	listenSocketPath := os.Getenv("LISTEN_SOCKET")
	if listenSocketPath == "" {
		return nil, fmt.Errorf("LISTEN_SOCKET must be set to unix socket path to listen on")
	}
	return &GlobalState{
		ThisEndpoint:     thisEndpoint,
		ListenSocketPath: listenSocketPath,
	}, nil
}

func NewOAuthApp(ctx context.Context, state *GlobalState) error {
	store, err := NewOAuthStore(ctx)
	if err != nil {
		return errors.Wrap(err, "creating oauth store")
	}
	state.Store = store

	config := oauth.NewPublicConfig(
		fmt.Sprintf("%s/client-metadata.json", state.ThisEndpoint),
		fmt.Sprintf("%s/v1/atproto/oauth/callback", state.ThisEndpoint),
		// []string{"atproto", "repo:com.fedproxy.rbac?action=read"},
		[]string{"atproto", "transition:generic"},
	)
	state.OAuthApp = oauth.NewClientApp(&config, store)
	return nil
}

func WithOAuthSession(state *GlobalState) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			runNext := func(s *oauth.ClientSessionData) {
				newCtx := context.WithValue(ctx, oauthSessionKey, s)
				next.ServeHTTP(w, r.WithContext(newCtx))
			}

			accountDIDCookie, err := r.Cookie("account_did")
			if err != nil {
				runNext(nil)
				return
			}

			did, err := syntax.ParseDID(accountDIDCookie.Value)
			if err != nil {
				log.Printf("invalid account_did cookie method=%s path=%s did=%s", r.Method, r.URL.Path, accountDIDCookie.Value)
				runNext(nil)
				return
			}

			// If no session_id cookie (e.g. after server restart with DB store), fall back to
			// looking up the most recent session for this DID in the store.
			sessionIdCookie, err := r.Cookie("session_id")
			if err != nil || sessionIdCookie.Value == "" {
				session, err := state.Store.GetSessionByDID(ctx, did)
				if err != nil {
					log.Printf("no session for did=%s method=%s path=%s", did, r.Method, r.URL.Path)
					runNext(nil)
					return
				}
				runNext(session)
				return
			}

			session, err := state.OAuthApp.Store.GetSession(ctx, did, sessionIdCookie.Value)
			if err != nil {
				log.Printf("session not found did=%s session_id=%s, trying DID fallback: %v", did, sessionIdCookie.Value, err)
				session, err = state.Store.GetSessionByDID(ctx, did)
				if err != nil {
					log.Printf("no session for did=%s method=%s path=%s", did, r.Method, r.URL.Path)
					runNext(nil)
					return
				}
			}

			runNext(session)
		})
	}
}

func realMain(ctx context.Context) error {
	state, err := NewGlobalState(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating GlobalState object")
	}
	if err := NewOAuthApp(ctx, state); err != nil {
		return errors.Wrap(err, "error creating atproto.oauth.ClientApp object")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/atproto/oauth/login", HandleLogin)
	mux.HandleFunc("GET /v1/atproto/oauth/callback", HandleOAuthCallback)
	mux.HandleFunc("GET /client-metadata.json", HandleClientMetadata)
	mux.HandleFunc("/", HandleProxy)

	handler := WithOAuthSession(state)(mux)
	return listenAndServe(ctx, state, handler)
}

func listenAndServe(ctx context.Context, state *GlobalState, handler http.Handler) error {
	socketPath := state.ListenSocketPath

	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			log.Fatalf("remove existing socket: %v", err)
		}
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix: %v", err)
	}
	defer func() {
		ln.Close()
		os.Remove(socketPath)
	}()

	if err := os.Chmod(socketPath, 0660); err != nil {
		return errors.Wrap(err, "failed to chmod 660 socket")
	}

	server := &http.Server{
		Handler: handler,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(ctx, globalStateKey, state)
		},
	}

	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("listening on unix socket %s", socketPath)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "context cancelled")
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
			if err := server.Close(); err != nil {
				log.Printf("force close error: %v", err)
			}
		}
		log.Println("server stopped")
	case err := <-serverErrCh:
		if err != nil {
			return errors.Wrap(err, "server error")
		}
		return nil
	}

	return nil
}

// ---------------------------------------------------------------------------
// RBAC types — mirror rbac.yaml / com.fedproxy.rbac record schema
// ---------------------------------------------------------------------------

type RBACRecord struct {
	Policies map[string]RBACPolicy `json:"policies"`
	Roles    map[string]RBACRole   `json:"roles"`
}

type RBACPolicy struct {
	Meta    map[string]string     `json:"meta"`
	Schemas map[string]RBACSchema `json:"schemas"` // XRPC path or glob → schema
}

// RBACSchema is the subset of the JSON Schema we enforce: the capability enum.
type RBACSchema struct {
	Properties struct {
		Capability struct {
			Enum []string `json:"enum"`
		} `json:"capability"`
	} `json:"properties"`
}

type RBACRole struct {
	RoleName   string             `json:"role_name"`
	Definition RBACRoleDefinition `json:"definition"`
}

type RBACRoleDefinition struct {
	// Iss is the OIDC issuer URL trusted for this role.
	// Mirrors role.definition.iss in rbac.yaml.
	Iss string `json:"iss"`
	// Aud is the expected audience for tokens presented for this role.
	Aud string `json:"aud"`
	// Sub is matched against the verified "sub" claim in the OIDC token.
	// This is NOT the DID/actx — it is whatever the issuer puts in sub
	// (e.g. "actx:...:role:my-cool-role" as in rbac.yaml).
	Sub      string   `json:"sub"`
	Policies []string `json:"policies"`
}

var httpMethodCapability = map[string]string{
	http.MethodGet:     "read",
	http.MethodHead:    "read",
	http.MethodOptions: "read",
	http.MethodPost:    "create",
	http.MethodPut:     "update",
	http.MethodPatch:   "update",
	http.MethodDelete:  "delete",
}

// ---------------------------------------------------------------------------
// ATProto: fetch RBAC record from PDS
// ---------------------------------------------------------------------------

// getRBACRecord paginates over all com.fedproxy.rbac records for did from
// pdsURL and merges them into a single RBACRecord by name-keyed join.
func getRBACRecord(ctx context.Context, pdsURL, did string) (*RBACRecord, error) {
	pds := &xrpc.Client{Host: pdsURL}

	joined := &RBACRecord{
		Policies: make(map[string]RBACPolicy),
		Roles:    make(map[string]RBACRole),
	}

	cursor := ""
	total := 0
	for {
		out, err := agnostic.RepoListRecords(ctx, pds, "com.fedproxy.rbac", cursor, 100, did, false)
		if err != nil {
			return nil, errors.Wrapf(err, "RepoListRecords pds=%s did=%s cursor=%s", pdsURL, did, cursor)
		}

		for _, rec := range out.Records {
			if rec == nil || rec.Value == nil {
				continue
			}
			var rbac RBACRecord
			if err := json.Unmarshal(*rec.Value, &rbac); err != nil {
				return nil, errors.Wrapf(err, "unmarshal RBACRecord uri=%s", rec.Uri)
			}
			for name, policy := range rbac.Policies {
				joined.Policies[name] = policy
			}
			for name, role := range rbac.Roles {
				joined.Roles[name] = role
			}
			total++
		}

		if out.Cursor == nil || *out.Cursor == "" {
			break
		}
		cursor = *out.Cursor
	}

	if total == 0 {
		return nil, fmt.Errorf("no com.fedproxy.rbac record found for did=%s", did)
	}

	roleNames := make([]string, 0, len(joined.Roles))
	for name := range joined.Roles {
		roleNames = append(roleNames, name)
	}
	policyNames := make([]string, 0, len(joined.Policies))
	for name := range joined.Policies {
		policyNames = append(policyNames, name)
	}
	log.Printf("loaded com.fedproxy.rbac did=%s records=%d roles=%v policies=%v",
		did, total, roleNames, policyNames)

	return joined, nil
}

// resolvePDS resolves a DID to its PDS endpoint URL via the ATProto identity
// directory (plc.directory for did:plc, /.well-known/did.json for did:web).
func resolvePDS(ctx context.Context, did string) (string, error) {
	id, err := syntax.ParseAtIdentifier(did)
	if err != nil {
		return "", errors.Wrap(err, "invalid at-identifier")
	}
	ident, err := identity.DefaultDirectory().Lookup(ctx, id)
	if err != nil {
		return "", errors.Wrap(err, "identity lookup failed")
	}
	pdsURL := ident.PDSEndpoint()
	if pdsURL == "" {
		return "", fmt.Errorf("no PDS endpoint in DID document for %s", did)
	}
	return pdsURL, nil
}

// ---------------------------------------------------------------------------
// OIDC token validation against RBAC record issuers
//
// Mirrors the flow in oidc_helper.OIDCToken.validate + rbac_helper.raise_if_unauthorized:
//
//  1. Peek at unverified aud to extract actx (DID) and api from
//     "api://<api>?actx=<did>".
//  2. Resolve the DID's PDS and fetch their com.fedproxy.rbac record.
//  3. Collect every role's definition.iss — these are the trusted issuers.
//  4. For each issuer fetch /.well-known/openid-configuration → jwks_uri,
//     fetch JWKS, and attempt full JWT verification (sig + exp + aud + iss).
//  5. On success, return the verified claims so the caller can do the
//     sub-based policy check (checkRBACPolicy).
// ---------------------------------------------------------------------------

// OIDCClaims holds the verified claims we care about from the token.
type OIDCClaims struct {
	Issuer   string // iss
	Audience string // aud  (the full "api://<api>?actx=<did>" string)
	Subject  string // sub  (matched against role.Definition.Sub)
	Actx     string // extracted from aud query param
	API      string // extracted from aud host segment
}

// providerCache holds *oidc.Provider instances keyed by issuer URL. NewProvider
// performs OIDC discovery (and the returned verifier caches JWKS), so this avoids
// re-fetching well-known config on every request.
var (
	providerCacheMu sync.RWMutex
	providerCache   = make(map[string]*oidc.Provider)
)

func getOIDCProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	providerCacheMu.RLock()
	p, ok := providerCache[issuer]
	providerCacheMu.RUnlock()
	if ok {
		return p, nil
	}
	providerCacheMu.Lock()
	defer providerCacheMu.Unlock()
	if p, ok := providerCache[issuer]; ok {
		return p, nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	providerCache[issuer] = p
	return p, nil
}

// validateOIDCToken implements the OIDCToken.validate logic from oidc_helper.py.
//
// It:
//  1. Peeks at the unverified aud to extract actx (DID) and api.
//  2. Resolves the DID's PDS, fetches the com.fedproxy.rbac record.
//  3. Collects every role.definition.iss → trusted issuer set.
//  4. For each issuer, runs go-oidc verification (discovery + JWKS + sig + iss + aud + exp).
//  5. Returns verified OIDCClaims and the RBAC record on success.
func validateOIDCToken(ctx context.Context, rawToken string) (*OIDCClaims, *RBACRecord, error) {
	if strings.Count(rawToken, ".") != 2 {
		return nil, nil, fmt.Errorf("malformed JWT")
	}

	// Step 1: peek at unverified payload to extract actx and api from aud.
	unverified, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse unverified JWT")
	}
	unverifiedClaims, ok := unverified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected claims type")
	}
	unverifiedAud, _ := unverifiedClaims["aud"].(string)
	actx, api, err := parseAudience(unverifiedAud)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse aud")
	}

	// Step 2: resolve DID → PDS → RBAC record.
	pdsURL, err := resolvePDS(ctx, actx)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "resolve PDS for actx=%s", actx)
	}
	rbac, err := getRBACRecord(ctx, pdsURL, actx)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "get RBAC record for actx=%s", actx)
	}

	// Step 3: collect trusted issuers from all roles.
	issuers := collectIssuers(rbac)
	if len(issuers) == 0 {
		return nil, nil, fmt.Errorf("no issuers defined in RBAC record for actx=%s", actx)
	}
	log.Printf("oidc: validating token actx=%s api=%s issuers=%v", actx, api, issuers)

	// Step 4: try each issuer — go-oidc handles discovery, JWKS, sig + iss + aud + exp.
	expectedAud := fmt.Sprintf("api://%s?actx=%s", api, actx)
	var lastErr error
	for _, issuer := range issuers {
		provider, err := getOIDCProvider(ctx, issuer)
		if err != nil {
			lastErr = errors.Wrapf(err, "issuer=%s provider", issuer)
			log.Printf("oidc: %v", lastErr)
			continue
		}

		verifier := provider.Verifier(&oidc.Config{
			ClientID: expectedAud,
		})
		idToken, err := verifier.Verify(ctx, rawToken)
		if err != nil {
			lastErr = errors.Wrapf(err, "issuer=%s verify", issuer)
			log.Printf("oidc: %v", lastErr)
			continue
		}

		var claims struct {
			Sub string `json:"sub"`
		}
		if err := idToken.Claims(&claims); err != nil {
			lastErr = errors.Wrapf(err, "issuer=%s decode claims", issuer)
			continue
		}

		log.Printf("oidc: token valid issuer=%s sub=%s actx=%s api=%s", issuer, claims.Sub, actx, api)
		return &OIDCClaims{
			Issuer:   idToken.Issuer,
			Audience: expectedAud,
			Subject:  claims.Sub,
			Actx:     actx,
			API:      api,
		}, rbac, nil
	}

	return nil, nil, errors.Wrap(lastErr, "OIDC token failed validation against all known issuers")
}

// parseAudience splits "api://<api>?actx=<did>" into (actx, api).
// Mirror: the aud parsing block in OIDCToken.validate.
func parseAudience(aud string) (actx, api string, err error) {
	// Strip leading "api://"
	rest, found := strings.CutPrefix(aud, "api://")
	if !found {
		return "", "", fmt.Errorf("aud does not start with api://: %q", aud)
	}
	// Split on "?" to separate api from query string.
	apiPart, query, found := strings.Cut(rest, "?")
	if !found {
		return "", "", fmt.Errorf("aud missing ?actx=: %q", aud)
	}
	// Parse query params manually — same as urllib.parse.parse_qs.
	for _, kv := range strings.Split(query, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == "actx" {
			return v, apiPart, nil
		}
	}
	return "", "", fmt.Errorf("aud does not have actx param: %q", aud)
}

// collectIssuers returns the unique set of iss values across all roles in the
// RBAC record. Mirror: get_issuers in rbac_helper.py.
func collectIssuers(rbac *RBACRecord) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, role := range rbac.Roles {
		iss := role.Definition.Iss
		if iss == "" {
			continue
		}
		if _, ok := seen[iss]; !ok {
			seen[iss] = struct{}{}
			out = append(out, iss)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Policy check — mirrors hcl_policy.check_permissions
//
// Matches roles by the verified "sub" claim (NOT the actx/DID), collects
// their policy names, finds the best matching path schema, checks capability.
// ---------------------------------------------------------------------------

// checkRBACPolicy returns nil if the request is permitted by at least one
// matching role+policy, or a descriptive error if denied.
//
// For cookie-session requests, sub == did (the account DID is the subject).
// For OIDC token requests, sub is whatever the issuer put in the token
// (e.g. "actx:...:role:my-cool-role") and must match role.Definition.Sub.
func checkRBACPolicy(rbac *RBACRecord, sub, path, httpMethod string) error {
	capability, ok := httpMethodCapability[httpMethod]
	if !ok {
		return fmt.Errorf("unsupported HTTP method %s", httpMethod)
	}

	// Collect all role definitions whose sub matches the token subject.
	// Mirror: the "Fallback to searching all roles by sub" branch in
	// check_permissions (we don't implement custom_claims_roles_index here
	// as it is not present in com.fedproxy.rbac records).
	var matchingPolicies []string
	for _, role := range rbac.Roles {
		if role.Definition.Sub != sub {
			continue
		}
		matchingPolicies = append(matchingPolicies, role.Definition.Policies...)
	}

	if len(matchingPolicies) == 0 {
		return fmt.Errorf("no matching role found for sub=%q", sub)
	}

	// Walk policies, find the best path schema, check the capability enum.
	var denials []string
	for _, policyName := range matchingPolicies {
		policy, exists := rbac.Policies[policyName]
		if !exists {
			continue
		}
		schema, matched := matchSchema(policy.Schemas, path)
		if !matched {
			continue
		}
		for _, c := range schema.Properties.Capability.Enum {
			if c == capability {
				return nil // permitted
			}
		}
		denials = append(denials,
			fmt.Sprintf("policy %q: capability %q not in %v for path %q",
				policyName, capability, schema.Properties.Capability.Enum, path))
	}

	if len(denials) > 0 {
		return fmt.Errorf("%s", strings.Join(denials, "; "))
	}
	return fmt.Errorf("no policy covers path=%q for sub=%q", path, sub)
}

// matchSchema returns the most specific schema whose key matches path.
// Exact match takes priority; otherwise the longest glob match wins.
// Mirror: find_matching_schema_for_path in hcl_policy.py.
func matchSchema(schemas map[string]RBACSchema, path string) (RBACSchema, bool) {
	if s, ok := schemas[path]; ok {
		return s, true
	}
	best := ""
	var bestSchema RBACSchema
	for pattern, schema := range schemas {
		if globMatch(pattern, path) && len(pattern) > len(best) {
			best = pattern
			bestSchema = schema
		}
	}
	return bestSchema, best != ""
}

// globMatch supports '*' wildcards only, consistent with Python fnmatch used
// in hcl_policy.py.
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	for {
		i := 0
		for i < len(pattern) && pattern[i] != '*' {
			i++
		}
		prefix := pattern[:i]
		if i == len(pattern) {
			return s == prefix
		}
		pattern = pattern[i+1:]
		if len(prefix) > 0 {
			found := -1
			for j := 0; j <= len(s)-len(prefix); j++ {
				if s[j:j+len(prefix)] == prefix {
					found = j
					break
				}
			}
			if found < 0 {
				return false
			}
			s = s[found+len(prefix):]
		}
		if len(pattern) == 0 {
			return true
		}
	}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// proxySource is the value of the "source" field on every JSON error this
// proxy emits. It distinguishes proxy-originated errors from upstream PDS
// responses, which are passed through unchanged.
const proxySource = "atproto-reverse-proxy"

// writeProxyError emits a JSON error response that is unambiguously identified
// as coming from this proxy. Error codes use a "Proxy" prefix and the
// `source: "atproto-reverse-proxy"` field so callers can tell proxy errors
// apart from upstream PDS errors. Upstream responses are never modified by
// this helper — they pass through ReverseProxy as-is.
func writeProxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "Proxy" + code,
		"message": message,
		"source":  proxySource,
	})
}

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		writeProxyError(w, http.StatusInternalServerError, "InternalError", "global state not found")
		return
	}

	identifier := r.URL.Query().Get("identifier")
	log.Printf("got identifier to start oauth flow method=%s path=%s identifier=%s", r.Method, r.URL.Path, identifier)

	redirectURL, err := state.OAuthApp.StartAuthFlow(ctx, identifier)
	if err != nil {
		log.Printf("error starting oauth flow method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		writeProxyError(w, http.StatusInternalServerError, "OAuthFlowStartFailed", err.Error())
		return
	}

	log.Printf("redirecting for oauth flow method=%s path=%s redirectURL=%s", r.Method, r.URL.Path, redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		writeProxyError(w, http.StatusInternalServerError, "InternalError", "global state not found")
		return
	}

	sessData, err := state.OAuthApp.ProcessCallback(ctx, r.URL.Query())
	if err != nil {
		log.Printf("error processing oauth callback method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		writeProxyError(w, http.StatusInternalServerError, "OAuthCallbackFailed", err.Error())
		return
	}

	log.Printf("oauth callback success method=%s path=%s did=%s scopes=%+v", r.Method, r.URL.Path, sessData.AccountDID, sessData.Scopes)

	if err := state.OAuthApp.Store.SaveSession(ctx, *sessData); err != nil {
		log.Printf("error saving session method=%s path=%s sessData=%+v", r.Method, r.URL.Path, sessData)
		writeProxyError(w, http.StatusInternalServerError, "SessionSaveFailed", err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "account_did",
		Value:    sessData.AccountDID.String(),
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessData.SessionID,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func HandleClientMetadata(w http.ResponseWriter, r *http.Request) {
	state := GlobalStateFromContext(r.Context())
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		writeProxyError(w, http.StatusInternalServerError, "InternalError", "global state not found")
		return
	}

	doc := state.OAuthApp.Config.ClientMetadata()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Printf("error encoding client metadata method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		writeProxyError(w, http.StatusInternalServerError, "ClientMetadataEncodeFailed", err.Error())
		return
	}
}

// HandleProxy is the catch-all reverse proxy. It supports two authentication
// paths, tried in this order:
//
//  1. Cookie session (account_did + session_id set by HandleOAuthCallback).
//     The session DID becomes the RBAC subject for policy matching.
//
//  2. OIDC Bearer token in the Authorization header (no cookies).
//     Mirrors raise_if_unauthorized in rbac_helper.py:
//     - Peeks at unverified aud to extract actx (DID) and api.
//     - Resolves DID → PDS → com.fedproxy.rbac record.
//     - Collects role.definition.iss values as trusted issuers.
//     - Validates JWT signature + claims against those issuers.
//     - Matches roles by verified sub claim, checks path + capability.
//
// All proxy-originated errors are emitted as JSON via writeProxyError so callers
// can distinguish them from upstream PDS responses (which pass through unchanged).
// In both cases the request is forwarded to the user's PDS once authorised.
func HandleProxy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("global state not found method=%s path=%s", r.Method, r.URL.Path)
		writeProxyError(w, http.StatusInternalServerError, "InternalError", "global state not found")
		return
	}

	var (
		pdsURL         string
		rbac           *RBACRecord
		sub            string
		proxyTransport http.RoundTripper
	)

	session := OAuthSessionFromContext(ctx)

	if session != nil {
		// --- Path 1: cookie session ---
		did := session.AccountDID.String()

		var err error
		pdsURL, err = resolvePDS(ctx, did)
		if err != nil {
			log.Printf("resolvePDS failed did=%s: %v", did, err)
			writeProxyError(w, http.StatusInternalServerError, "IdentityLookupFailed", fmt.Sprintf("resolvePDS for did=%s: %v", did, err))
			return
		}

		rbac, err = getRBACRecord(ctx, pdsURL, did)
		if err != nil {
			log.Printf("getRBACRecord failed did=%s pds=%s: %v", did, pdsURL, err)
			writeProxyError(w, http.StatusForbidden, "RBACLoadFailed", fmt.Sprintf("failed to load RBAC config for did=%s: %v", did, err))
			return
		}

		// For cookie sessions the subject is the account DID itself.
		sub = did

		sess, err := state.OAuthApp.ResumeSession(ctx, session.AccountDID, session.SessionID)
		if err != nil {
			log.Printf("ResumeSession failed did=%s: %v", did, err)
			writeProxyError(w, http.StatusInternalServerError, "SessionResumeFailed", fmt.Sprintf("session resume failed for did=%s: %v", did, err))
			return
		}
		proxyTransport = &oauthRoundTripper{sess: sess}

	} else {
		// --- Path 2: OIDC Bearer token ---
		authHeader := r.Header.Get("Authorization")
		rawToken, found := strings.CutPrefix(authHeader, "Bearer ")
		if !found || rawToken == "" {
			log.Printf("unauthenticated request method=%s path=%s", r.Method, r.URL.Path)
			writeProxyError(w, http.StatusUnauthorized, "Unauthenticated",
				fmt.Sprintf("not logged in — visit %s/v1/atproto/oauth/login?identifier=<handle>", state.ThisEndpoint))
			return
		}

		// validateOIDCToken resolves actx→PDS→RBAC, collects issuers from
		// role definitions, verifies the JWT, and returns verified claims.
		claims, rbacFromToken, err := validateOIDCToken(ctx, rawToken)
		if err != nil {
			log.Printf("oidc validation failed method=%s path=%s: %v", r.Method, r.URL.Path, err)
			writeProxyError(w, http.StatusUnauthorized, "OIDCValidationFailed", err.Error())
			return
		}

		rbac = rbacFromToken
		sub = claims.Subject // verified sub — matched against role.Definition.Sub

		// Resolve the PDS for the actx DID so we know where to proxy.
		pdsURL, err = resolvePDS(ctx, claims.Actx)
		if err != nil {
			log.Printf("resolvePDS failed actx=%s: %v", claims.Actx, err)
			writeProxyError(w, http.StatusInternalServerError, "IdentityLookupFailed", fmt.Sprintf("resolvePDS for actx=%s: %v", claims.Actx, err))
			return
		}

		// Require a stored ATProto OAuth session for the actx DID — the PDS
		// only accepts ATProto DPoP auth, not OIDC tokens.
		actxDID, parseErr := syntax.ParseDID(claims.Actx)
		if parseErr != nil {
			log.Printf("invalid actx DID=%s: %v", claims.Actx, parseErr)
			writeProxyError(w, http.StatusBadRequest, "InvalidActx", fmt.Sprintf("invalid actx in token: %v", parseErr))
			return
		}
		dbSess, dbErr := state.Store.GetSessionByDID(ctx, actxDID)
		if dbErr != nil {
			log.Printf("no ATProto session for actx=%s: %v", claims.Actx, dbErr)
			writeProxyError(w, http.StatusUnauthorized, "NoATProtoSession",
				fmt.Sprintf("no ATProto session for actx=%s: log in via %s/v1/atproto/oauth/login first", claims.Actx, state.ThisEndpoint))
			return
		}
		atSess, resumeErr := state.OAuthApp.ResumeSession(ctx, dbSess.AccountDID, dbSess.SessionID)
		if resumeErr != nil {
			log.Printf("ResumeSession failed for actx=%s: %v", claims.Actx, resumeErr)
			writeProxyError(w, http.StatusInternalServerError, "SessionResumeFailed", fmt.Sprintf("ATProto session resume failed for actx=%s: %v", claims.Actx, resumeErr))
			return
		}
		proxyTransport = &oauthRoundTripper{sess: atSess}
	}

	// Policy check — same code path for both auth methods.
	// Mirror: hcl_policy.check_permissions matching by sub.
	if err := checkRBACPolicy(rbac, sub, r.URL.Path, r.Method); err != nil {
		log.Printf("rbac denied sub=%s method=%s path=%s: %v", sub, r.Method, r.URL.Path, err)
		writeProxyError(w, http.StatusForbidden, "RBACDenied", err.Error())
		return
	}

	// Reverse-proxy to PDS. Past this point, response bodies come from upstream
	// and pass through unchanged. Only the ErrorHandler below — which fires for
	// transport-level failures (DNS, TCP, TLS, token refresh) — emits a proxy
	// error. HTTP error responses from the PDS itself are NOT remapped.
	target, err := url.Parse(pdsURL)
	if err != nil {
		log.Printf("invalid pdsURL=%s: %v", pdsURL, err)
		writeProxyError(w, http.StatusInternalServerError, "InvalidPDSURL", fmt.Sprintf("invalid PDS URL %q: %v", pdsURL, err))
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			for _, h := range []string{
				"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
				"X-Real-IP", "Via", "Forwarded",
			} {
				req.Header.Del(h)
			}
		},
		Transport: proxyTransport,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			log.Printf("proxy error method=%s path=%s pds=%s: %v", req.Method, req.URL.Path, pdsURL, err)
			writeProxyError(w, http.StatusBadGateway, "UpstreamUnreachable", fmt.Sprintf("could not reach PDS %s: %v", pdsURL, err))
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Transfer-Encoding")
			return nil
		},
	}

	log.Printf("proxying sub=%s method=%s path=%s -> %s", sub, r.Method, r.URL.Path, pdsURL)
	proxy.ServeHTTP(w, r)
}

// Ensure io is used (for potential future body draining).
var _ = io.Discard
