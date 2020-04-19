package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"

	"github.com/joncooperworks/wireguardhttps"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.App{
		Commands: []*cli.Command{
			{
				Name:        "initialize",
				Usage:       "sets up the database tables and allocates IP addresses in the provided subnet",
				Description: "sets up database tables and IP addresses in the given subnet",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "subnet",
						Value: "10.0.0.0/24",
						Usage: "the client device subnet in valid CIDR notation (example: 10.0.0.0/24)",
					},
				},
				Action: actionInitialize,
			},
			{
				Name:        "serve",
				Usage:       "starts the web application",
				Description: "starts the web application",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "wireguard-listen-port",
						Value: 51820,
						Usage: "the port the Wireguard VPN listens on",
					},
					&cli.StringFlag{
						Name:  "wireguard-host",
						Usage: "the fully qualified domain name of the Wireguard server",
					},
					&cli.StringSliceFlag{
						Name:  "client-dns",
						Usage: "a list of DNS server IP addresses for clients",
						Value: cli.NewStringSlice("1.1.1.1"),
					},
					&cli.StringFlag{
						Name:  "wgrpcd-address",
						Value: "localhost:15002",
						Usage: "the wgrpcd gRPC server on localhost. It must be running to run this program.",
					},
					&cli.IntFlag{
						Name:  "web-listen-port",
						Value: 443,
						Usage: "port to listen on",
					},
					&cli.BoolFlag{
						Name:  "http-insecure",
						Value: false,
						Usage: "listen over insecure http instead of https. not recommended for production",
					},
					&cli.StringFlag{
						Name:  "templates-directory",
						Usage: "directory containing templates for Wireguard config",
					},
				},
				Action: actionServe,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}

func prompt() {
	log.Println("wireguardhttps 0.0.1")
	log.Println("This software has not been audited.\nVulnerabilities in this can compromise your server and user data.\nDo not run this in production")
}

func actionInitialize(c *cli.Context) error {
	subnet := c.String("subnet")
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("--subnet must be a subnet specified in valid CIDR notation, got %v", subnet)
	}
	addressRange := &wireguardhttps.AddressRange{Network: *network}
	prompt()
	log.Println(addressRange.Addresses())
	return nil
}

func actionServe(c *cli.Context) error {
	serverHostName := c.String("wireguard-host")
	wireguardListenPort := c.Int("wireguard-listen-port")
	if serverHostName == "" {
		return fmt.Errorf("--wireguard-host argument is required.")
	}

	url, err := url.Parse(fmt.Sprintf("%v:%v", serverHostName, wireguardListenPort))
	if err != nil {
		return fmt.Errorf("--wireguard-host must be a valid URL, got %v", serverHostName)
	}

	dnsServers, err := stringsToIPs(c.StringSlice("client-dns"))
	if err != nil {
		return fmt.Errorf("--client-dns must be valid IP addresses. %v", err)
	}

	templatesDirectory := c.String("templates-directory")

	config := &wireguardhttps.ServerConfig{
		DNSServers:         dnsServers,
		Endpoint:           url,
		TemplatesDirectory: templatesDirectory,
	}

	prompt()
	log.Println(config)
	return nil
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
