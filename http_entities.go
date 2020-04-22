package wireguardhttps

import (
	"net"
	"net/url"
)


type DeviceRequest struct{
	Name string `json:"name"`
	OS string `json:"os"`
}

type DeviceConfigINI struct{
	PrivateKey string
	PublicKey string
	Addresses []net.IP
	DNSAddresses []net.IP
	AllowedIPs []net.IP
	Endpoint *url.URL
}
