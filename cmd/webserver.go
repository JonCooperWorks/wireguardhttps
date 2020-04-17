package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/joncooperworks/wireguardhttps"
)

var (
	wgrpcdAddress            = flag.String("wgrpcd-address", "localhost:15002", "-wgrpcd-address is the wgrpcd gRPC server on localhost. It must be running to run this program.")
	serverHostName           = flag.String("server-host", "", "-server-host is the fully qualified domain name of the webserver. Used for SSL and Wireguard config generation.")
	wireguardListenPort      = flag.Int("wireguard-listen-port", 51820, "-wireguard-listen-port is the port the Wireguard VPN is listening on.")
	commaSeparatedDNSServers = flag.String("dns-servers", "1.1.1.1", "-dns-servers is a comma separated list of DNS server IP addresses.")
	subnet                   = flag.String("subnet", "10.0.0.0/24", "-subnet is the address space for device IP addresses to be allocated in, specified in CIDR notation.")
)

func init() {
	flag.Parse()
}

func main() {
	log.Println("wireguardhttps 0.0.1")
	log.Println("This software has not been audited.\nVulnerabilities in this can compromise your server and user data.\nDo not run this in production")

	if *serverHostName == "" {
		log.Fatalln("-server-host argument is required.")
	}

	url, err := url.Parse(fmt.Sprintf("%v:%v", *serverHostName, *wireguardListenPort))
	if err != nil {
		log.Fatalln("-server-host must be a valid URL, got", *serverHostName)
	}

	_, network, err := net.ParseCIDR(*subnet)
	if err != nil {
		log.Fatalln("-subnet must be a subnet specified in valid CIDR notation, got", *subnet)
	}
	addressRange := &wireguardhttps.AddressRange{Network: *network}
	dnsServers, err := stringsToIPs(strings.Split(*commaSeparatedDNSServers, ","))
	if err != nil {
		log.Fatalln("-dns-servers must be valid IP addresses.", err.Error())
	}

	// TODO: Pass this to HTTP handlers.
	_ = &wireguardhttps.ServerConfig{
		Endpoint:   url,
		Subnet:     addressRange,
		DNSServers: dnsServers,
	}
}

func stringsToIPs(rawIPs []string) ([]net.IP, error) {
	ips := []net.IP{}
	for _, rawIP := range rawIPs {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			return []net.IP{}, fmt.Errorf("%v is not a valid IP address", ip)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}
