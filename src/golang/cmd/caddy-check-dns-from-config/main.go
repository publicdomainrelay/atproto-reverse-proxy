// caddy-check-dns-from-config implements the HTTP endpoint used by Caddy's
// `on_demand_tls.ask` directive. It reads the running Caddy config over the
// admin Unix socket (the same socket used by cmd/atprp-ssh-relay) and only
// authorizes a certificate request when the requested FQDN appears as an
// exact host matcher in one of Caddy's HTTP server routes.
//
// This makes wildcard-cert / DNS-01 issuance safe: Caddy will gladly issue
// a cert for any name the wildcard policy covers, but the gate here ensures
// it only does so for names atprp-ssh-relay (or the static Caddyfile) has
// actually registered.
//
// Caddy's `ask` HTTP client cannot dial Unix sockets, so this service
// listens on TCP loopback.
//
// Usage:
//
//	CADDY_SOCK=${PWD}/caddy-admin.sock \
//	LISTEN_ADDR=127.0.0.1:5555 \
//	go run cmd/caddy-check-dns-from-config/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

type matcherSet struct {
	Host []string `json:"host,omitempty"`
}

type route struct {
	ID    string       `json:"@id,omitempty"`
	Match []matcherSet `json:"match,omitempty"`
}

type httpServer struct {
	Routes []route `json:"routes,omitempty"`
}

type caddyConfig struct {
	Apps struct {
		HTTP struct {
			Servers map[string]httpServer `json:"servers,omitempty"`
		} `json:"http,omitempty"`
	} `json:"apps,omitempty"`
}

func getCaddyClient(caddySockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", caddySockPath)
			},
		},
	}
}

func fetchHosts(ctx context.Context, client *http.Client) (map[string]struct{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/config/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch caddy config: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("caddy admin returned %d: %s", resp.StatusCode, string(body))
	}
	var cfg caddyConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode caddy config: %w", err)
	}
	hosts := make(map[string]struct{})
	for _, srv := range cfg.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			for _, m := range r.Match {
				for _, h := range m.Host {
					h = strings.ToLower(strings.TrimSpace(h))
					if h == "" {
						continue
					}
					hosts[h] = struct{}{}
				}
			}
		}
	}
	return hosts, nil
}

// hostAllows reports whether the configured-route host pattern grants a cert
// for the requested name. We match exact hostnames and single-label `*.suffix`
// wildcards. Bare wildcards like `*` (everything) are intentionally ignored —
// otherwise the catch-all entry from the Caddyfile would defeat the gate.
func hostAllows(pattern, requested string) bool {
	if pattern == requested {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:] // ".rest.example.com"
	if !strings.HasSuffix(requested, suffix) {
		return false
	}
	label := requested[:len(requested)-len(suffix)]
	if label == "" || strings.Contains(label, ".") {
		return false
	}
	return true
}

func main() {
	caddySock := os.Getenv("CADDY_SOCK")
	if caddySock == "" {
		log.Fatal("CADDY_SOCK must be set to the caddy admin unix socket path")
	}
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:5555"
	}

	client := getCaddyClient(caddySock)

	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
		if domain == "" {
			http.Error(w, "missing domain", http.StatusBadRequest)
			return
		}

		hosts, err := fetchHosts(r.Context(), client)
		if err != nil {
			log.Printf("⚠️ check error domain=%s: %v", domain, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		for pattern := range hosts {
			if hostAllows(pattern, domain) {
				log.Printf("✅ allow domain=%s matched=%s", domain, pattern)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		log.Printf("⛔ deny domain=%s (no matching route in caddy config)", domain)
		http.Error(w, "no matching route", http.StatusNotFound)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("▶️ caddy-check-dns-from-config listening on %s caddy_sock=%s", listenAddr, caddySock)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal(err)
	}
}
