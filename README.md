# oidcrp

`import "github.com/kilo666mj/oidcrp"`

A small OpenID Connect **relying-party** helper for Go web apps that authenticate
humans through an OIDC provider (e.g. Pocket ID). It handles the browser-facing
half of the flow and leaves session storage to the app.

The package owns:

- OIDC discovery.
- Authorization-code flow with PKCE.
- State and nonce cookies.
- ID token verification.
- Subject, email, and group allowlists.
- Browser auth middleware decisions.

Apps still own local sessions by implementing `SessionManager`.

```go
auth := oidcrp.New(oidcrp.Config{
    Issuer:          cfg.OIDC.Issuer,
    ClientID:        cfg.OIDC.ClientID,
    ClientSecret:    cfg.OIDC.ClientSecret,
    RedirectURL:     cfg.OIDC.RedirectURL,
    Scopes:          cfg.OIDC.Scopes,
    AllowedEmails:   cfg.OIDC.AllowedEmails,
    AllowedGroups:   cfg.OIDC.AllowedGroups,
    StateCookieName: "myapp_oidc",
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
    Issue(w http.ResponseWriter, r *http.Request, identity oidcrp.Identity) error
    Clear(w http.ResponseWriter, r *http.Request)
}
```

## License

MIT — see [LICENSE](LICENSE).
