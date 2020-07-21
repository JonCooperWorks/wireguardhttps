package wireguardhttps

import (
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/secure"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	adapter "github.com/gwatts/gin-adapter"
	"github.com/markbates/goth"
)

func Router(config *ServerConfig) *gin.Engine {
	goth.UseProviders(config.AuthProviders...)
	gob.Register(&UserProfile{})
	router := gin.Default()

	router.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{"/api/"})))

	whitelist := []string{}
	for _, origin := range config.CDNWhitelist {
		whitelist = append(whitelist, origin.String())
	}
	csp := fmt.Sprintf("default-src 'self'; object-src 'none'; base-uri 'none';  require-trusted-types-for 'script'; %s", strings.Join(whitelist, " "))
	router.Use(secure.New(
		secure.Config{
			BrowserXssFilter:      true,
			IENoOpen:              true,
			FrameDeny:             true,
			ContentSecurityPolicy: csp,
			ContentTypeNosniff:    true,
			SSLRedirect:           !config.IsDebug,
			IsDevelopment:         config.IsDebug,
			AllowedHosts:          []string{config.HTTPHost.String()},
			SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		}),
	)

	// JavaScript SPA frontend
	router.Use(static.Serve("/", static.LocalFile(config.StaticAssetsDir, true)))

	handlers := &WireguardHandlers{ServerConfig: config}

	// API
	api := router.Group("/api")

	// Authentication
	auth := api.Group("/auth")
	auth.Use(ProviderWhitelistMiddleware)
	auth.GET("/callback", handlers.OAuthCallbackHandler)
	auth.GET("/authenticate", handlers.AuthenticateHandler)
	auth.GET("/logout", handlers.LogoutHandler)

	// Private routes
	private := api.Group("/")
	private.Use(AuthenticationRequiredMiddleware(config.SessionStore, config.SessionName))

	if !config.IsDebug {
		csrfMiddleware := csrf.Protect(config.CSRFKey)
		private.Use(adapter.Wrap(csrfMiddleware))
	}

	// Devices
	devices := private.Group("/devices")
	devices.GET("/", handlers.ListUserDevicesHandler)
	devices.POST("/", handlers.NewDeviceHandler)
	devices.POST("/:device_id", handlers.RekeyDeviceHandler)
	devices.DELETE("/:device_id", handlers.DeleteDeviceHandler)
	devices.GET("/:device_id/traffic", handlers.StreamPCAPHandler)

	// User Profile
	private.GET("/me", handlers.UserProfileInfoHandler)

	return router
}
