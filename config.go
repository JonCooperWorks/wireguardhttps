package wireguardhttps

import (
	"net"
	"net/url"
)

type ServerConfig struct {
	Subnet   net.IPNet
	DNSs     net.IP
	Endpoint url.URL
}
