# internal-oidc

Shared OpenID Connect relying-party helper for internal Go apps that authenticate
humans through Pocket ID.

The package owns:

- OIDC discovery.
- Authorization-code flow with PKCE.
- State and nonce cookies.
- ID token verification.
- Subject, email, and group allowlists.
- Browser auth middleware decisions.

Apps still own local sessions by implementing `SessionManager`.

```go
auth := internaloidc.New(internaloidc.Config{
    Issuer:          cfg.OIDC.Issuer,
    ClientID:        cfg.OIDC.ClientID,
    ClientSecret:    cfg.OIDC.ClientSecret,
    RedirectURL:     cfg.OIDC.RedirectURL,
    Scopes:          cfg.OIDC.Scopes,
    AllowedEmails:   cfg.OIDC.AllowedEmails,
    AllowedGroups:   cfg.OIDC.AllowedGroups,
    StateCookieName: "fleetglass_oidc",
    LoginPath:       "/login",
    SuccessPath:     "/",
    APIPrefixes:     []string{"/api/"},
}, sessions)

auth.Register(mux)
mux.HandleFunc("POST /api/auth/logout", auth.Logout)
mux.HandleFunc("GET /", auth.Require(app.index))
```

`SessionManager` is intentionally small:

```go
type SessionManager interface {
    Valid(r *http.Request) bool
    Issue(w http.ResponseWriter, r *http.Request, identity internaloidc.Identity) error
    Clear(w http.ResponseWriter, r *http.Request)
}
```
