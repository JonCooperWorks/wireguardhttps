package wireguardhttps

import (
	"net"
	"net/url"
	"text/template"

	"github.com/gorilla/sessions"
	"github.com/joncooperworks/wgrpcd"
	"github.com/markbates/goth"
)

// ServerConfig contains all info needed to configure a WireguardHTTPS instance.
type ServerConfig struct {
	DNSServers          []net.IP
	Endpoint            *url.URL
	HTTPHost            *url.URL
	Templates           map[string]*template.Template
	WireguardDeviceName string
	WireguardClient     *wgrpcd.Client
	Database            Database
	AuthProviders       []goth.Provider
	IsDebug             bool
	SessionStore        sessions.Store
	SessionName         string
	CSRFKey             []byte
	StaticAssetsDir     string
	CDNWhitelist        []*url.URL
	MaxCookieAge        int
	IsHeroku            bool
}
