package wireguardhttps

import (
	"net"
	"net/url"
)

type ServerConfig struct {
	DNSServers         []net.IP
	Endpoint           *url.URL
	TemplatesDirectory string
}
