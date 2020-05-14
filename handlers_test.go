package wireguardhttps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/azuread"
)

func TestOnlyWhitelistedAuthProvidersAccepted(t *testing.T) {
	httpHost, _ := url.Parse("localhost")
	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
		HTTPHost: httpHost,
		IsDebug:  true,
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

func TestAuthenticatedURLsFailWithoutSession(t *testing.T) {
	httpHost, _ := url.Parse("localhost")
	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
		HTTPHost:     httpHost,
		IsDebug:      true,
		SessionStore: gothic.Store,
		SessionName:  "wgsessions",
	}
	testRouter := Router(config)
	writer := httptest.NewRecorder()

	urls := []string{
		"/me",
		"/devices",
	}

	for _, url := range urls {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatal(err)
		}
		testRouter.ServeHTTP(writer, request)

		if writer.Code != 401 {
			t.Fatalf("Expected status code 401 for %v, got %v", url, writer.Code)
		}
	}
}

func TestProfileEndpointReturnsCorrectInfo(t *testing.T) {
	httpHost, _ := url.Parse("localhost")
	sessionStore := gothic.Store
	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
		HTTPHost:     httpHost,
		IsDebug:      true,
		SessionStore: sessionStore,
		SessionName:  "wgsessions",
	}
	testRouter := Router(config)
	writer := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/me", nil)
	if err != nil {
		t.Fatal(err)
	}

	session, err := sessionStore.Get(request, config.SessionName)
	if err != nil {
		t.Fatal(err)
	}

	expectedUser := UserProfile{
		AuthPlatform:       "azuread",
		AuthPlatformUserID: "jontom@adtenant.com",
	}
	session.Values["user"] = &expectedUser
	err = session.Save(request, writer)
	if err != nil {
		t.Fatal(err)
	}

	testRouter.ServeHTTP(writer, request)

	if writer.Code != 200 {
		t.Fatalf("Expected status code 200 for /me, got %v", writer.Code)
	}
	var user UserProfile
	err = json.NewDecoder(writer.Body).Decode(&user)
	if err != nil {
		t.Fatal(err)
	}

	if user.AuthPlatform != expectedUser.AuthPlatform && user.AuthPlatformUserID != expectedUser.AuthPlatformUserID {
		t.Fatalf("Expected %v got, %v", expectedUser, user)
	}
}
