package wireguardhttps

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/joncooperworks/wgrpcd"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/azuread"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	testPrivateKey      = "private"
	testPublicKey       = "public"
	testServerPublicKey = "serverpublic"
	testDNSServer       = "1.1.1.1"
	testServerName      = "gateway.myprivate.network:51820"
)

var (
	expectedPeerConfig = `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = ` + testAllowedIP.String() + `
DNS = ` + testDNSServer + `

[Peer]
PublicKey = ` + testServerPublicKey + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ` + testServerName
)

var (
	_, testAllowedIP, _ = net.ParseCIDR("10.0.0.1/32")
	testPeerConfigInfo  = &wgrpcd.PeerConfigInfo{
		PrivateKey:      testPrivateKey,
		PublicKey:       testPublicKey,
		AllowedIPs:      []net.IPNet{*testAllowedIP},
		ServerPublicKey: testServerPublicKey,
	}
)

type testwgrpcdClient struct{}

func (t *testwgrpcdClient) CreatePeer(ctx context.Context, allowedIPs []net.IPNet) (*wgrpcd.PeerConfigInfo, error) {
	return testPeerConfigInfo, nil
}

func (t *testwgrpcdClient) RekeyPeer(ctx context.Context, oldPublicKey wgtypes.Key, allowedIPs []net.IPNet) (*wgrpcd.PeerConfigInfo, error) {
	return nil, nil
}

func (t *testwgrpcdClient) ChangeListenPort(ctx context.Context, listenPort int) (int32, error) {
	return int32(listenPort), nil
}

func (t *testwgrpcdClient) RemovePeer(ctx context.Context, publicKey wgtypes.Key) (bool, error) {
	return true, nil
}

func (t *testwgrpcdClient) ListPeers(ctx context.Context) ([]*wgrpcd.Peer, error) {
	return []*wgrpcd.Peer{}, nil
}

func (t *testwgrpcdClient) Devices(ctx context.Context) ([]string, error) {
	return []string{}, nil
}

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

func TestCreateDevicesRecordsCorrectInfoInDatabase(t *testing.T) {
	httpHost, _ := url.Parse("localhost")
	sessionStore := gothic.Store
	db, err := NewSQLiteDatabase(":memory:")
	if err != nil {
		t.Fatalf(err.Error())
	}

	defer db.Close()
	err = db.Initialize()
	if err != nil {
		t.Fatalf(err.Error())
	}

	err = db.AllocateSubnet([]net.IP{net.ParseIP("10.0.0.0"), net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")})
	if err != nil {
		t.Fatalf(err.Error())
	}

	config := &ServerConfig{
		AuthProviders: []goth.Provider{
			azuread.New("key", "secret", "localhost:80/callback", nil),
		},
		HTTPHost:        httpHost,
		IsDebug:         true,
		SessionStore:    sessionStore,
		SessionName:     "wgsessions",
		Database:        db,
		WireguardClient: &testwgrpcdClient{},
	}
	testRouter := Router(config)
	writer := httptest.NewRecorder()

	deviceRequest := DeviceRequest{
		Name: "Macbook Pro",
		OS:   "iOS",
	}

	jsonBody, _ := json.Marshal(deviceRequest)
	request, err := http.NewRequest("POST", "/devices", bytes.NewReader(jsonBody))
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
		t.Fatalf("Expected status code 200 for /devices, got %v", writer.Code)
	}

	actualPeerConfig, _ := ioutil.ReadAll(writer.Body)
	if expectedPeerConfig != string(actualPeerConfig) {
		t.Fatalf("Expected:\n%v\nGot:\n%v", expectedPeerConfig, actualPeerConfig)
	}

}
