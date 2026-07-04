package internaloidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memorySessions struct {
	valid  bool
	issued *Identity
	clear  bool
}

func (m *memorySessions) Valid(*http.Request) bool {
	return m.valid
}

func (m *memorySessions) Issue(_ http.ResponseWriter, _ *http.Request, identity Identity) error {
	m.issued = &identity
	return nil
}

func (m *memorySessions) Clear(http.ResponseWriter, *http.Request) {
	m.clear = true
}

func TestNewNormalizesDefaults(t *testing.T) {
	auth := New(Config{
		Issuer:        "https://pocket-id.internal",
		ClientID:      "app",
		RedirectURL:   "https://app.internal/api/auth/callback",
		AllowedGroups: []string{"admins"},
	}, &memorySessions{})

	if !auth.Enabled() {
		t.Fatal("auth should be enabled")
	}
	if !auth.SecureCookies() {
		t.Fatal("secure cookies should be enabled for https redirect URLs")
	}
	if auth.cfg.StateCookieName != defaultStateCookieName {
		t.Fatalf("StateCookieName = %q", auth.cfg.StateCookieName)
	}
	if !containsFold(auth.cfg.Scopes, "groups") {
		t.Fatalf("Scopes = %v, want groups scope appended", auth.cfg.Scopes)
	}
}

func TestRequireAllowsWhenDisabled(t *testing.T) {
	auth := New(Config{}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	auth.Require(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestRequireRedirectsBrowserGET(t *testing.T) {
	auth := New(Config{
		Issuer:      "https://pocket-id.internal",
		ClientID:    "app",
		RedirectURL: "https://app.internal/api/auth/callback",
		LoginPath:   "/login",
	}, &memorySessions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/review", nil)

	auth.Require(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next should not be called")
	})(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("Location = %q, want /login", got)
	}
}

func TestRequireRejectsAPI(t *testing.T) {
	auth := New(Config{
		Issuer:      "https://pocket-id.internal",
		ClientID:    "app",
		RedirectURL: "https://app.internal/api/auth/callback",
		APIPrefixes: []string{"/api/"},
	}, &memorySessions{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)

	auth.Require(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next should not be called")
	})(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAllowedAcceptsConfiguredEmailCaseInsensitively(t *testing.T) {
	auth := New(Config{AllowedEmails: []string{"Admin@Example.com"}}, nil)

	if !auth.allowed(Identity{Subject: "sub", Email: "admin@example.com"}) {
		t.Fatal("expected configured email to be accepted")
	}
	if auth.allowed(Identity{Subject: "sub", Email: "other@example.com"}) {
		t.Fatal("unexpected email should be rejected")
	}
}

func TestRedirectLoginErrorEscapesMessage(t *testing.T) {
	auth := New(Config{LoginPath: "/login"}, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/callback", nil)

	auth.redirectLoginError(rec, req, "bad state & retry")

	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.Contains(location, "bad+state+%26+retry") {
		t.Fatalf("status=%d Location=%q", rec.Code, location)
	}
}
