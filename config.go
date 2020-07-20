package wireguardhttps

import (
	"net"
	"net/url"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/joncooperworks/wgrpcd"
	"github.com/markbates/goth"
)

type ServerConfig struct {
	DNSServers      []net.IP
	Endpoint        *url.URL
	HTTPHost        *url.URL
	Templates       map[string]*template.Template
	WireguardClient wgrpcd.Client
	Database        Database
	AuthProviders   []goth.Provider
	IsDebug         bool
	SessionStore    sessions.Store
	SessionName     string
	CSRFKey         []byte
	StaticAssetsDir string
	CDNWhitelist    []*url.URL
	MaxCookieAge    int
	PacketStream    *PacketStream
}
