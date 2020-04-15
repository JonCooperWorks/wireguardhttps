package wireguardhttps

import (
	"net"
	"net/url"
)

type ServerConfig struct {
	Subnet *AddressRange
	DNSs     net.IP
	Endpoint url.URL
}
