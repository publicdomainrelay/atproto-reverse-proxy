package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/pkg/errors"
)

type GlobalState struct {
	ThisEndpoint     string
	ListenSocketPath string
	OAuthApp         *oauth.ClientApp
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

func OAuthSessionFromContext(ctx context.Context) *GlobalState {
	if v := ctx.Value(oauthSessionKey); v != nil {
		if s, ok := v.(*oauth.ClientSessionData); ok {
			return s
		}
	}
	return nil
}

func main() {
	ctx := context.Background()

	err := realMain(ctx)
	if err != nil {
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
	config := oauth.NewPublicConfig(
		fmt.Sprintf("%s/client-metadata.json", state.ThisEndpoint),
		fmt.Sprintf("%s/oauth/callback", state.ThisEndpoint),
		[]string{"atproto", "repo:com.fedproxy.sshPublicKey?action=create"},
	)

	// clients are "public" by default, but if they have secure access to a secret attestation key can be "confidential"
	/*
		if CLIENT_SECRET_KEY != "" {
			priv, err := crypto.ParsePrivateMultibase(CLIENT_SECRET_KEY)
			if err != nil {
				return err
			}
			if err := config.SetClientSecret(priv, "example1"); err != nil {
				return err
			}
		}
	*/

	state.OAuthApp = oauth.NewClientApp(&config, oauth.NewMemStore())

	return nil
}

func WithOAuthSession(state *GlobalState) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var ctx *context.Context
			did, err := r.Cookie("session_id")
			if err != nil {
				log.Printf("error getting cookie=account_did method=%s path=%s", r.Method, r.URL.Path)
				ctx = context.WithValue(r.Context(), oauthSessionKey, nil)
			} else {
				session, err := state.OAuthApp.GetSession(ctx, sessionId)
				log.Printf("error getting session method=%s path=%s session_id=%s", r.Method, r.URL.Path, sessionId)
				if err != nil {
					ctx = context.WithValue(r.Context(), oauthSessionKey, nil)
				} else {
					ctx = context.WithValue(r.Context(), oauthSessionKey, session)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func realMain(ctx context.Context) error {
	state, err := NewGlobalState(ctx)
	if err != nil {
		return errors.Wrap(err, "error creating GlobalState object")
	}

	err = NewOAuthApp(ctx, state)
	if err != nil {
		return errors.Wrap(err, "error creating atproto.oauth.ClientApp object")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", HandleServeRoot)
	mux.HandleFunc("GET /client-metadata.json", HandleClientMetadata)
	mux.HandleFunc("GET /oauth/login", HandleLogin)
	mux.HandleFunc("GET /oauth/callback", HandleOAuthCallback)

	handler := WithOAuthSession()(mux)

	return listenAndServe(ctx, state, handler)
}

func listenAndServe(ctx context.Context, state *GlobalState, handler http.Handler) error {
	socketPath := state.ListenSocketPath

	// Clean up existing socket file if present.
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			log.Fatalf("remove existing socket: %v", err)
		}
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen unix: %v", err)
	}
	// ensure socket is removed on exit
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
			ctx := context.WithValue(r.Context(), globalStateKey, state)
			return ctx
		},
	}

	// Start server in background.
	serverErrCh := make(chan error, 1)
	go func() {
		log.Printf("listening on unix socket %s", socketPath)
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	// Handle signals for graceful shutdown (SIGINT, SIGTERM).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		return errors.Wrap(ctx.Err(), "context cancelled")
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down...", sig)
		// allow up to 10s for graceful shutdown; adjust as needed
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
			// force close
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

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		http.Error(w, "global state not found", http.StatusInternalServerError)
		return
	}

	oauthApp := state.OAuthApp

	// parse login identifier from the request
	query := r.URL.Query()
	identifier := query.Get("identifier")
	log.Printf("got identifier to start oauth flow method=%s path=%s identifier=%s", r.Method, r.URL.Path, identifier)

	redirectURL, err := oauthApp.StartAuthFlow(ctx, identifier)
	if err != nil {
		log.Printf("error starting oauth flow method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	log.Printf("redirecting for oauth flow method=%s path=%s redirectURL=%s", r.Method, r.URL.Path, redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		http.Error(w, "global state not found", http.StatusInternalServerError)
		return
	}

	oauthApp := state.OAuthApp

	sessData, err := oauthApp.ProcessCallback(ctx, r.URL.Query())
	if err != nil {
		log.Printf("error processing oauth callback method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	log.Printf("oauth callback success method=%s path=%s did=%s scopes=%+v", r.Method, r.URL.Path, sessData.AccountDID, sessData.Scopes)

	// TODO HSTS, CSP, etc.
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
		http.Error(w, "global state not found", http.StatusInternalServerError)
		return
	}

	oauthApp := state.OAuthApp

	doc := oauthApp.Config.ClientMetadata()

	// if this is is a confidential client, need to set doc.JWKSURI, and implement a handler

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Printf("error encoding client metadata method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func HandleServeRoot(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	state := GlobalStateFromContext(ctx)
	if state == nil {
		log.Printf("error while serving request global state not found method=%s path=%s", r.Method, r.URL.Path)
		http.Error(w, "global state not found", http.StatusInternalServerError)
		return
	}

	oauthApp := state.OAuthApp

	doc := oauthApp.Config.ClientMetadata()

	session := OAuthSessionFromContext(ctx)
	if session == nil {
		log.Printf("oauth session not found method=%s path=%s", r.Method, r.URL.Path)
		//
		http.Error(w, fmt.Sprintf("%s/oauth/login?identifier=${handle}.bsky.social", state.ThisEndpoint), http.OK)
		return
	}

	did, err := r.Cookie("account_did")
	if err != nil {
		// User not logged in
		// TODO Serve form for redirect to login page and example ssh from client

		log.Printf("error getting cookie=account_did method=%s path=%s", r.Method, r.URL.Path)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("got did method=%s path=%s did=%s", r.Method, r.URL.Path, did)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		log.Printf("error encoding client metadata method=%s path=%s: %+v", r.Method, r.URL.Path, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO Support update of public keys
	// oauthApp.GetSession(ctx, did, sessionId)
	/*
		fedproxyatp.GetSSHPublicKeys(ctx, did)

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
		}

		// if this is is a confidential client, need to set doc.JWKSURI, and implement a handler
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(sshPublicKey); err != nil {
			log.Printf("error encoding client metadata method=%s path=%s: %+v", r.Method, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	*/
}

/*
func DoSomethingWithOAuthSession() {
	// web services might use a secure session cookie to determine user's DID for a request
	did := syntax.DID("did:plc:abc123")
	sessionID := "xyz"

	sess, err := oauthApp.ResumeSession(ctx, did, sessionID)
	if err != nil {
		return err
	}

	c := sess.APIClient()

	body := map[string]any{
		"repo":       *c.AccountDID,
		"collection": "app.bsky.feed.post",
		"record": map[string]any{
			"$type":     "app.bsky.feed.post",
			"text":      "Hello World via OAuth!",
			"createdAt": syntax.DatetimeNow(),
		},
	}

	if err := c.Post(ctx, "com.atproto.repo.createRecord", body, nil); err != nil {
		return err
	}

	if err := oauthApp.Logout(r.Context(), did, sessionID); err != nil {
		return err
	}
}
*/
