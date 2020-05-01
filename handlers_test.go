package wireguardhttps

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/azuread"
)

func TestOnlyWhitelistedAuthProvidersAccepted(t *testing.T) {
	httpHost, _ := url.Parse("localhost")
	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
		HTTPHost: httpHost,
	}
	testRouter := Router(config)
	writer := httptest.NewRecorder()

	urls := []string{
		"/auth/callback?provider=stripe",
		"/auth/authenticate?provider=stripe",
		"/auth/logout?provider=stripe",
		"/auth/authenticate",
		"/auth/logout",
		"/auth/callback",
	}
	for _, url := range urls {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		testRouter.ServeHTTP(writer, request)

		if writer.Code != 400 {
			t.Fatalf("Expected status code 400 for %v, got %v", url, writer.Code)
		}
	}
}
