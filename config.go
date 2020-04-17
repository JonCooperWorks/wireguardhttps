package wireguardhttps

import (
	"net"
	"net/url"
)

type ServerConfig struct {
	Subnet     *AddressRange
	DNSServers []net.IP
	Endpoint   *url.URL
}
