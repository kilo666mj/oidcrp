package oidcrp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memorySessions struct {
	valid          bool
	issued         *Identity
	desktopIssued  *Identity
	desktopHandoff string
	clear          bool
}

func (m *memorySessions) IssueDesktop(_ http.ResponseWriter, _ *http.Request, identity Identity, handoff string) error {
	m.desktopIssued = &identity
	m.desktopHandoff = handoff
	return nil
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

func TestDesktopHandoffValidation(t *testing.T) {
	sessions := &memorySessions{valid: true}
	auth := New(Config{
		DesktopHandoffParam: "desktop",
		ValidateDesktopHandoff: func(value string) bool {
			return value == "valid-handoff"
		},
	}, sessions)

	ordinary := httptest.NewRequest(http.MethodGet, "/api/auth/login/start", nil)
	if value, err := auth.desktopHandoff(ordinary); err != nil || value != "" {
		t.Fatalf("ordinary handoff = %q, %v", value, err)
	}
	valid := httptest.NewRequest(http.MethodGet, "/api/auth/login/start?desktop=valid-handoff", nil)
	if value, err := auth.desktopHandoff(valid); err != nil || value != "valid-handoff" {
		t.Fatalf("valid handoff = %q, %v", value, err)
	}
	invalid := httptest.NewRequest(http.MethodGet, "/api/auth/login/start?desktop=invalid", nil)
	if _, err := auth.desktopHandoff(invalid); err == nil {
		t.Fatal("invalid desktop handoff was accepted")
	}
}

type browserOnlySessions struct{ memorySessions }

func TestDesktopHandoffRequiresDesktopSessionManager(t *testing.T) {
	var sessions SessionManager = &browserOnlySessionManager{}
	auth := New(Config{DesktopHandoffParam: "desktop", ValidateDesktopHandoff: func(string) bool { return true }}, sessions)
	request := httptest.NewRequest(http.MethodGet, "/api/auth/login/start?desktop=value", nil)
	if _, err := auth.desktopHandoff(request); err == nil {
		t.Fatal("desktop handoff was accepted without DesktopSessionManager")
	}
}

func TestVerifiedIdentityUsesDesktopSessionManager(t *testing.T) {
	sessions := &memorySessions{}
	auth := New(Config{SuccessPath: "/", DesktopHandoffParam: "desktop", DesktopSuccessPath: "/desktop/complete", ValidateDesktopHandoff: func(string) bool { return true }}, sessions)
	identity := Identity{Subject: "subject-1", Email: "person@example.com"}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/auth/callback", nil)
	if err := auth.issueVerifiedIdentity(response, request, identity, pendingAuth{DesktopHandoff: "handoff"}); err != nil {
		t.Fatal(err)
	}
	if sessions.desktopIssued == nil || sessions.desktopIssued.Subject != identity.Subject || sessions.desktopHandoff != "handoff" {
		t.Fatalf("desktop issue = %+v, %q", sessions.desktopIssued, sessions.desktopHandoff)
	}
	if sessions.issued != nil {
		t.Fatal("ordinary browser session was issued during desktop handoff")
	}
	if got := response.Header().Get("Location"); got != "/desktop/complete" {
		t.Fatalf("Location = %q", got)
	}
}

type browserOnlySessionManager struct{}

func (*browserOnlySessionManager) Valid(*http.Request) bool { return false }
func (*browserOnlySessionManager) Issue(http.ResponseWriter, *http.Request, Identity) error {
	return nil
}
func (*browserOnlySessionManager) Clear(http.ResponseWriter, *http.Request) {}
