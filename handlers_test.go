package wireguardhttps

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/azuread"
)

func TestOnlyWhitelistedAuthProvidersAccepted(t *testing.T) {
	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
	}
	testRouter := Router(config)
	writer := httptest.NewRecorder()

	urls := []string{
		"/auth/callback?provider=stripe",
		"/auth/authenticate?provider=stripe",
		"/auth/logout?provider=stripe",
	}
	for _, url := range urls {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		testRouter.ServeHTTP(writer, request)
	
		if writer.Code != 400 {
			t.Fatalf("Expected status code 400, got %v", writer.Code)
		}
	}
}