# oidcrp

`import "github.com/kilo666mj/oidcrp"`

A small OpenID Connect **relying-party** helper for Go web apps that authenticate
humans through an OIDC provider (e.g. Pocket ID). It handles the browser-facing
half of the flow and leaves session storage to the app.

## Install and reference

```sh
go get github.com/kilo666mj/oidcrp@v0.2.0
```

`oidcrp` requires Go 1.26.5 or newer. The compatibility lane also tests the
current Go release. API documentation is available on
[pkg.go.dev](https://pkg.go.dev/github.com/kilo666mj/oidcrp).

The package owns:

- OIDC discovery.
- Authorization-code flow with PKCE.
- State and nonce cookies.
- ID token verification.
- Subject, email, and group allowlists.
- Browser auth middleware decisions.

Apps still own local sessions by implementing `SessionManager`.

Native shells can keep credentials out of an embedded webview by enabling a
desktop handoff. The shell generates an opaque one-time value and opens the
ordinary login URL in the system browser. After verifying the OIDC response,
`oidcrp` passes that value and the identity to `DesktopSessionManager`; the app
then exposes its own same-origin, single-use session exchange endpoint.

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

For a desktop handoff, add these fields and implement the optional interface:

```go
auth := oidcrp.New(oidcrp.Config{
    // ordinary OIDC fields omitted
    DesktopHandoffParam:    "desktop",
    DesktopSuccessPath:     "/auth/desktop/complete",
    ValidateDesktopHandoff: validOneTimeCode,
}, sessions)

func (s *sessions) IssueDesktop(w http.ResponseWriter, r *http.Request,
    identity oidcrp.Identity, handoff string) error {
    return s.storePendingIdentity(r.Context(), handoff, identity)
}
```

The handoff is not a session token. It should be high entropy, expire quickly,
be consumed atomically, and be rotated into a normal HttpOnly application
session by the native webview.

`SessionManager` is intentionally small:

```go
type SessionManager interface {
    Valid(r *http.Request) bool
    Issue(w http.ResponseWriter, r *http.Request, identity oidcrp.Identity) error
    Clear(w http.ResponseWriter, r *http.Request)
}
```

## Adoption checklist

1. Register an exact HTTPS callback URL with the identity provider.
2. Implement `SessionManager` with application-owned, HttpOnly sessions and
   explicit expiry and revocation.
3. Configure subject, email, or group allowlists when the provider is shared.
4. Mount the standard routes, protect browser handlers with `Require`, and keep
   API prefixes on the `401` path rather than browser redirects.
5. Preserve the request scheme and host through the reverse proxy; test state,
   nonce, PKCE, callback, logout, and provider-outage behavior.
6. For native handoffs, make the opaque value high entropy, short-lived, and
   atomically single-use before exchanging it for an application session.

The package does not own account provisioning, local roles, session storage,
reverse-proxy trust, or provider availability. Those remain application and
deployment policy.

## License

MIT — see [LICENSE](LICENSE).
