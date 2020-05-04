package wireguardhttps

import (
	"net"
	"net/url"
)


type DeviceRequest struct{
	Name string `json:"name"`
	OS string `json:"os"`
}

type PeerConfigINI struct{
	PublicKey string
	PrivateKey string
	AllowedIPs []string
	Addresses []string
	DNSServers []string
	ServerName string
}