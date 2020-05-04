package wireguardhttps


type PeerConfigINI struct{
	PublicKey string
	PrivateKey string
	AllowedIPs []string
	Addresses []string
	DNSServers []string
	ServerName string
}