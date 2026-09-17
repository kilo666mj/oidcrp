package oidcrp_test

import (
	"fmt"
	"net/http"

	"github.com/kilo666mj/oidcrp"
)

type exampleSessions struct{}

func (*exampleSessions) Valid(*http.Request) bool { return false }
func (*exampleSessions) Issue(http.ResponseWriter, *http.Request, oidcrp.Identity) error {
	return nil
}
func (*exampleSessions) Clear(http.ResponseWriter, *http.Request) {}

func ExampleNew() {
	auth := oidcrp.New(oidcrp.Config{
		Issuer:        "https://id.example.com",
		ClientID:      "docs-app",
		RedirectURL:   "https://app.example.com/api/auth/callback",
		AllowedGroups: []string{"operators"},
		APIPrefixes:   []string{"/api/"},
	}, &exampleSessions{})

	mux := http.NewServeMux()
	auth.Register(mux)
	mux.HandleFunc("GET /", auth.Require(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("signed in"))
	}))

	fmt.Println(auth.Enabled(), auth.SecureCookies())
	// Output: true true
}
