package oidcrp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	defaultStateCookieName = "internal_oidc"
	defaultLoginPath       = "/login"
	defaultLoginStartPath  = "/api/auth/login/start"
	defaultCallbackPath    = "/api/auth/callback"
	defaultSuccessPath     = "/"
)

// Config defines the OIDC relying-party behavior shared by internal Go apps.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	AllowedSubjects []string
	AllowedEmails   []string
	AllowedGroups   []string

	StateCookieName string
	LoginPath       string
	LoginStartPath  string
	CallbackPath    string
	SuccessPath     string
	APIPrefixes     []string

	HTTPClient *http.Client
	Logger     *log.Logger
}

// Identity is the verified identity returned by the OIDC provider.
type Identity struct {
	Subject string
	Email   string
	Groups  []string
}

// SessionManager is implemented by each app's local session store.
type SessionManager interface {
	Valid(r *http.Request) bool
	Issue(w http.ResponseWriter, r *http.Request, identity Identity) error
	Clear(w http.ResponseWriter, r *http.Request)
}

// Service owns the browser OIDC flow and delegates durable sessions to the app.
type Service struct {
	cfg      Config
	sessions SessionManager

	httpClient *http.Client
	oidcMu     sync.Mutex
	provider   *oidc.Provider
	verifier   *oidc.IDTokenVerifier
	oauth      *oauth2.Config
}

type pendingAuth struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
}

// New returns an OIDC service. The service is disabled until issuer, client ID,
// and redirect URL are all configured.
func New(cfg Config, sessions SessionManager) *Service {
	cfg.normalize()
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Service{cfg: cfg, sessions: sessions, httpClient: client}
}

func (c *Config) normalize() {
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	if len(c.AllowedGroups) > 0 && !containsFold(c.Scopes, "groups") {
		c.Scopes = append(c.Scopes, "groups")
	}
	if strings.TrimSpace(c.StateCookieName) == "" {
		c.StateCookieName = defaultStateCookieName
	}
	if strings.TrimSpace(c.LoginPath) == "" {
		c.LoginPath = defaultLoginPath
	}
	if strings.TrimSpace(c.LoginStartPath) == "" {
		c.LoginStartPath = defaultLoginStartPath
	}
	if strings.TrimSpace(c.CallbackPath) == "" {
		c.CallbackPath = defaultCallbackPath
	}
	if strings.TrimSpace(c.SuccessPath) == "" {
		c.SuccessPath = defaultSuccessPath
	}
}

// Enabled reports whether OIDC auth should be active.
func (s *Service) Enabled() bool {
	return strings.TrimSpace(s.cfg.Issuer) != "" &&
		strings.TrimSpace(s.cfg.ClientID) != "" &&
		strings.TrimSpace(s.cfg.RedirectURL) != ""
}

// SecureCookies reports whether auth cookies should carry the Secure attribute.
func (s *Service) SecureCookies() bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s.cfg.RedirectURL)), "https://")
}

// Register adds the standard OIDC routes to a ServeMux.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+s.cfg.LoginStartPath, s.LoginStart)
	mux.HandleFunc("GET "+s.cfg.CallbackPath, s.Callback)
}

// Require protects a handler with the configured browser auth policy.
func (s *Service) Require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Enabled() || (s.sessions != nil && s.sessions.Valid(r)) {
			next(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		for _, prefix := range s.cfg.APIPrefixes {
			if prefix != "" && strings.HasPrefix(r.URL.Path, prefix) {
				http.Error(w, "not authenticated", http.StatusUnauthorized)
				return
			}
		}
		http.Redirect(w, r, s.cfg.LoginPath, http.StatusFound)
	}
}

// LoginStart begins the authorization-code + PKCE login flow.
func (s *Service) LoginStart(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		http.NotFound(w, r)
		return
	}
	if s.sessions != nil && s.sessions.Valid(r) {
		http.Redirect(w, r, s.cfg.SuccessPath, http.StatusFound)
		return
	}
	if err := s.ensureOIDC(r.Context()); err != nil {
		s.logf("oidc: %v", err)
		s.redirectLoginError(w, r, "identity provider is unavailable, try again")
		return
	}
	state := randToken()
	nonce := randToken()
	verifier := oauth2.GenerateVerifier()
	s.setPendingCookie(w, pendingAuth{State: state, Nonce: nonce, Verifier: verifier})
	authURL := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback completes the OIDC flow and asks the app to issue its local session.
func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		http.NotFound(w, r)
		return
	}
	if s.sessions == nil {
		http.Error(w, "session manager is not configured", http.StatusInternalServerError)
		return
	}
	if err := s.ensureOIDC(r.Context()); err != nil {
		s.logf("oidc: %v", err)
		s.redirectLoginError(w, r, "identity provider is unavailable, try again")
		return
	}
	pending, err := s.readPendingCookie(r)
	s.clearPendingCookie(w)
	if err != nil {
		s.redirectLoginError(w, r, "sign-in session expired, try again")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		if desc := q.Get("error_description"); desc != "" {
			e = desc
		}
		s.redirectLoginError(w, r, e)
		return
	}
	if q.Get("state") == "" || q.Get("state") != pending.State {
		s.redirectLoginError(w, r, "invalid sign-in state, try again")
		return
	}

	ctx := oidc.ClientContext(r.Context(), s.httpClient)
	token, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		s.logf("oidc: code exchange: %v", err)
		s.redirectLoginError(w, r, "sign-in failed, try again")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.redirectLoginError(w, r, "identity provider returned no ID token")
		return
	}
	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.logf("oidc: verify id token: %v", err)
		s.redirectLoginError(w, r, "could not verify identity, try again")
		return
	}
	if idToken.Nonce != pending.Nonce {
		s.redirectLoginError(w, r, "invalid sign-in nonce, try again")
		return
	}
	var claims struct {
		Email  string   `json:"email"`
		Groups []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		s.logf("oidc: decode claims: %v", err)
		s.redirectLoginError(w, r, "sign-in failed, try again")
		return
	}
	identity := Identity{Subject: idToken.Subject, Email: claims.Email, Groups: claims.Groups}
	if !s.allowed(identity) {
		s.logf("oidc: rejected sub=%q email=%q (not in allowlist)", identity.Subject, identity.Email)
		s.redirectLoginError(w, r, "your account is not permitted to sign in")
		return
	}
	if err := s.sessions.Issue(w, r, identity); err != nil {
		s.logf("oidc: issue session: %v", err)
		s.redirectLoginError(w, r, "sign-in failed, try again")
		return
	}
	http.Redirect(w, r, s.cfg.SuccessPath, http.StatusFound)
}

// Logout clears the app's local session.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if s.sessions != nil {
		s.sessions.Clear(w, r)
	}
	http.Redirect(w, r, s.cfg.LoginPath, http.StatusFound)
}

func (s *Service) ensureOIDC(ctx context.Context) error {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.provider != nil {
		return nil
	}
	ctx = oidc.ClientContext(ctx, s.httpClient)
	provider, err := oidc.NewProvider(ctx, strings.TrimSpace(s.cfg.Issuer))
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	s.provider = provider
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.cfg.ClientID})
	s.oauth = &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.cfg.RedirectURL,
		Scopes:       s.cfg.Scopes,
	}
	return nil
}

func (s *Service) allowed(identity Identity) bool {
	if len(s.cfg.AllowedSubjects) == 0 && len(s.cfg.AllowedEmails) == 0 && len(s.cfg.AllowedGroups) == 0 {
		return true
	}
	for _, subject := range s.cfg.AllowedSubjects {
		if subject == identity.Subject {
			return true
		}
	}
	for _, email := range s.cfg.AllowedEmails {
		if strings.EqualFold(strings.TrimSpace(email), identity.Email) {
			return true
		}
	}
	for _, group := range s.cfg.AllowedGroups {
		if containsFold(identity.Groups, group) {
			return true
		}
	}
	return false
}

func (s *Service) redirectLoginError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, s.cfg.LoginPath+"?error="+url.QueryEscape(msg), http.StatusFound)
}

func (s *Service) setPendingCookie(w http.ResponseWriter, p pendingAuth) {
	data, _ := json.Marshal(p)
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.StateCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(data),
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) readPendingCookie(r *http.Request) (pendingAuth, error) {
	cookie, err := r.Cookie(s.cfg.StateCookieName)
	if err != nil {
		return pendingAuth{}, err
	}
	data, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return pendingAuth{}, err
	}
	var p pendingAuth
	if err := json.Unmarshal(data, &p); err != nil {
		return pendingAuth{}, err
	}
	if p.State == "" || p.Nonce == "" || p.Verifier == "" {
		return pendingAuth{}, fmt.Errorf("incomplete pending auth")
	}
	return p, nil
}

func (s *Service) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.StateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("read random: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func containsFold(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}
