package oidcrp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeProvider is a minimal OIDC provider that signs ID tokens with extra
// claims and echoes the nonce from the authorization request.
func fakeProvider(t *testing.T, clientID string, extra map[string]any) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var nonce string
	provider := httptest.NewUnstartedServer(nil)
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	provider.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/authorize":
			mu.Lock()
			nonce = r.URL.Query().Get("nonce")
			mu.Unlock()
			redirect, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
			q := redirect.Query()
			q.Set("state", r.URL.Query().Get("state"))
			q.Set("code", "code")
			redirect.RawQuery = q.Encode()
			http.Redirect(w, r, redirect.String(), http.StatusFound)
		case "/token":
			mu.Lock()
			claims := map[string]any{"nonce": nonce}
			mu.Unlock()
			for k, v := range extra {
				claims[k] = v
			}
			now := time.Now()
			raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: provider.URL, Subject: "subject-1", Audience: jwt.Audience{clientID}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Hour))}).Claims(claims).Serialize()
			if err != nil {
				http.Error(w, "sign", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"access_token": "a", "token_type": "Bearer", "expires_in": 3600, "id_token": raw})
		case "/keys":
			writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: string(jose.RS256), Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	})
	provider.Start()
	t.Cleanup(provider.Close)
	return provider
}

func runLogin(t *testing.T, extra map[string]any) *memorySessions {
	t.Helper()
	provider := fakeProvider(t, "app", extra)
	sessions := &memorySessions{}
	app := httptest.NewUnstartedServer(nil)
	appURL := "http://" + app.Listener.Addr().String()
	auth := New(Config{Issuer: provider.URL, ClientID: "app", RedirectURL: appURL + defaultCallbackPath}, sessions)
	mux := http.NewServeMux()
	auth.Register(mux)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	app.Config.Handler = mux
	app.Start()
	t.Cleanup(app.Close)

	jar, _ := cookiejar.New(nil)
	resp, err := (&http.Client{Jar: jar}).Get(appURL + defaultLoginStartPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Request.URL.Path != defaultSuccessPath || resp.Request.URL.RawQuery != "" {
		t.Fatalf("login ended at %s", resp.Request.URL)
	}
	if sessions.issued == nil {
		t.Fatal("no session issued")
	}
	return sessions
}

func TestCallbackIssuesIdentityWithClaims(t *testing.T) {
	sessions := runLogin(t, map[string]any{"email": "a@example.com", "email_verified": true, "groups": []string{"admins"}, "preferred_username": "alice"})
	got := sessions.issued
	if got.Subject != "subject-1" || got.Email != "a@example.com" || !got.EmailVerified {
		t.Fatalf("identity = %+v", got)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "admins" {
		t.Fatalf("groups = %v", got.Groups)
	}
	if got.Claims["preferred_username"] != "alice" || got.Claims["sub"] != "subject-1" {
		t.Fatalf("claims = %v", got.Claims)
	}
}

func TestCallbackReportsUnverifiedEmail(t *testing.T) {
	sessions := runLogin(t, map[string]any{"email": "a@example.com"})
	if sessions.issued.EmailVerified {
		t.Fatal("email without email_verified claim was reported verified")
	}
}
