package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/joncooperworks/wgrpcd"
	"github.com/joncooperworks/wireguardhttps"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/azureadv2"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	app := cli.App{
		Usage:       "The easier way to use Wireguard",
		Description: "Allows Wireguard management via HTTPS.",
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
					&cli.StringFlag{
						Name:     "connection-string",
						Usage:    "postgresql database connection string",
						Required: true,
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
						Name:     "wireguard-host",
						Usage:    "the fully qualified domain name of the Wireguard server",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "http-host",
						Usage:    "the fully qualified domain name of the wireguardhttps server",
						Required: true,
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
					&cli.StringFlag{
						Name:  "http-listen-addr",
						Value: ":443",
						Usage: "the port to listen for http requests on",
					},
					&cli.PathFlag{
						Name:     "templates-directory",
						Usage:    "directory containing templates for Wireguard config",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "wireguard-device",
						Value: "wg0",
						Usage: "wireguard device name as shown in network interfaces",
					},
					&cli.StringFlag{
						Name:     "connection-string",
						Usage:    "postgresql database connection strings",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "azure-ad-key",
						Usage:    "azure ad client key",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "azure-ad-secret",
						Usage:    "azure ad client secret",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "azure-ad-callback-url",
						Usage:    "azure ad oauth callback url",
						Required: true,
					},
					&cli.BoolFlag{
						Name:  "debug",
						Value: false,
						Usage: "run server in debug mode",
					},
					&cli.StringFlag{
						Name:  "api-session-name",
						Value: "wireguardhttpssession",
						Usage: "session cookie name. you can change this to mess with pentesters and automatic scanners.",
					},
					&cli.StringFlag{
						Name:  "csrf-session-key",
						Usage: "key for signing CSRF tokens. keep as safe as the session key.",
					},
					&cli.StringFlag{
						Name:     "ad-tenant",
						Usage:    "ad tenant name",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "session-secret",
						Usage:    "cookie signing key",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "static-assets-dir",
						Usage:    "frontend js app",
						Required: true,
					},
					&cli.StringSliceFlag{
						Name:     "allowed-cdn",
						Usage:    "whitelisted CDNs for the CSP",
						Required: false,
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

func checkWireguardDevice(wireguardDevice string, foundDevices []string) bool {
	for _, device := range foundDevices {
		if wireguardDevice == device {
			return true
		}
	}

	return false
}

func actionInitialize(c *cli.Context) error {
	subnet := c.String("subnet")
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return fmt.Errorf("--subnet must be a subnet specified in valid CIDR notation, got %v", subnet)
	}
	addressRange := &wireguardhttps.AddressRange{Network: *network}
	prompt()
	log.Println("Allocating IP addresses in", network)

	connectionString := c.String("connection-string")
	database, err := wireguardhttps.NewPostgresDatabase(connectionString)
	if err != nil {
		return err
	}
	defer database.Close()

	err = database.Initialize()
	if err != nil {
		return err
	}

	addresses := addressRange.Addresses()
	err = database.AllocateSubnet(addresses)
	if err != nil {
		return err
	}

	// We don't allocate the server, network or broadcast addresses.
	log.Printf("Allocated %v addresses in %v\n", len(addresses)-3, network)
	return nil
}

func actionServe(c *cli.Context) error {
	serverHostName := c.String("wireguard-host")
	wireguardListenPort := c.Int("wireguard-listen-port")

	endpointURL, err := url.Parse(fmt.Sprintf("%v:%v", serverHostName, wireguardListenPort))
	if err != nil {
		return fmt.Errorf("--wireguard-host must be a valid URL, got %v", serverHostName)
	}

	httpHost, err := url.Parse(c.String("http-host"))
	if err != nil {
		return fmt.Errorf("--http-host must be a valid URL, got %v", httpHost)
	}

	dnsServers, err := wgrpcd.StringsToIPs(c.StringSlice("client-dns"))
	if err != nil {
		return fmt.Errorf("--client-dns must be valid IP addresses. %v", err)
	}

	templatesDirectory := c.Path("templates-directory")
	wgRPCdAddress := c.String("wgrpcd-address")
	wireguardDevice := c.String("wireguard-device")
	connectionString := c.String("connection-string")
	azureADKey := c.String("azure-ad-key")
	azureADSecret := c.String("azure-ad-secret")
	azureADCallbackURL := c.String("azure-ad-callback-url")
	listenAddr := c.String("http-listen-addr")

	database, err := wireguardhttps.NewPostgresDatabase(connectionString)
	if err != nil {
		return err
	}
	defer database.Close()

	err = database.Initialize()
	if err != nil {
		return err
	}

	wireguardClient := &wgrpcd.GRPCClient{
		GrpcAddress: wgRPCdAddress,
		DeviceName:  wireguardDevice,
	}

	devices, err := wireguardClient.Devices(context.Background())
	if err != nil {
		return err
	}

	addresses, err := database.Addresses()
	if err != nil {
		return err
	}

	if len(addresses) == 0 {
		return fmt.Errorf("allocate a subnet first with initialize")
	}

	if !checkWireguardDevice(wireguardDevice, devices) {
		return fmt.Errorf("%v is not a Wireguard device. Found %v", wireguardDevice, devices)
	}

	templates := map[string]*template.Template{
		"peer_config": template.Must(
			template.New("peerconfig.tmpl").
				Funcs(map[string]interface{}{"StringsJoin": strings.Join}).
				ParseFiles(filepath.Join(templatesDirectory, "ini/peerconfig.tmpl")),
		),
	}

	debugMode := c.Bool("debug")

	// Prevent running gin in debug mode by accident
	if !debugMode {
		gin.SetMode(gin.ReleaseMode)
	}

	csrfSessionKey := []byte(c.String("csrf-session-key"))
	if !debugMode && len(csrfSessionKey) != 32 {
		return fmt.Errorf("CSRF session key must be 32 bytes, got %v", len(csrfSessionKey))
	}

	store := sessions.NewFilesystemStore(os.TempDir(), []byte(c.String("session-secret")))
	maxCookieAge := 86400 * 30
	store.MaxAge(maxCookieAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true
	store.Options.Secure = !debugMode
	store.MaxLength(math.MaxInt64)
	gothic.Store = store

	cdnWhitelist := []*url.URL{}
	for _, cdn := range c.StringSlice("allowed-cdn") {
		origin, err := url.Parse(cdn)
		if err != nil {
			return fmt.Errorf("--allowed-cdn must be a valid URL, got %v", httpHost)
		}
		cdnWhitelist = append(cdnWhitelist, origin)
	}

	packetStream := wireguardhttps.NewPacketStream(wireguardDevice)

	config := &wireguardhttps.ServerConfig{
		DNSServers:      dnsServers,
		Endpoint:        endpointURL,
		HTTPHost:        httpHost,
		Templates:       templates,
		WireguardClient: wireguardClient,
		Database:        database,
		AuthProviders: []goth.Provider{
			azureadv2.New(azureADKey, azureADSecret, azureADCallbackURL, azureadv2.ProviderOptions{Tenant: azureadv2.TenantType(c.String("ad-tenant"))}),
		},
		SessionStore:    gothic.Store,
		SessionName:     c.String("api-session-name"),
		IsDebug:         debugMode,
		CSRFKey:         csrfSessionKey,
		StaticAssetsDir: c.String("static-assets-dir"),
		MaxCookieAge:    maxCookieAge,
		PacketStream:    packetStream,
	}

	router := wireguardhttps.Router(config)

	prompt()

	// Make packets from the VPN interface available to the web app
	go packetStream.Capture()

	if config.IsDebug {
		return router.Run(listenAddr)
	}

	hostname := httpHost.String()
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hostname),
		Cache:      autocert.DirCache(cacheDir(hostname)),
	}

	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		CipherSuites: []uint16{
			// TLSv1.3
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,

			// TLSv1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         ":https",
		TLSConfig:    tlsConfig,
		Handler:      router,
	}
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))

	return server.ListenAndServeTLS("", "")
}

func cacheDir(hostname string) (dir string) {
	dir = filepath.Join(os.TempDir(), "cache-golang-autocert-"+hostname)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		log.Println("Found cache dir:", dir)
		return dir
	}
	if err := os.MkdirAll(dir, 0700); err == nil {
		return dir
	}

	panic("couldnt create cert cache directory")
}
