package wireguardhttps

import (
	"net"
	"net/url"

	"github.com/joncooperworks/wgrpcd"
	"github.com/markbates/goth"
)

type ServerConfig struct {
	DNSServers         []net.IP
	Endpoint           *url.URL
	HTTPHost           *url.URL
	TemplatesDirectory string
	WireguardClient    *wgrpcd.Client
	Database           Database
	AuthProviders      []goth.Provider
}
