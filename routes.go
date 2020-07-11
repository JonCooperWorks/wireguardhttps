package wireguardhttps

import (
	"encoding/gob"

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
	router.Use(secure.New(
		secure.Config{
			BrowserXssFilter:      true,
			IENoOpen:              true,
			FrameDeny:             true,
			ContentSecurityPolicy: "default-src 'self'",
			ContentTypeNosniff:    true,
			SSLRedirect:           !config.IsDebug,
			IsDevelopment:         config.IsDebug,
			AllowedHosts:          []string{config.HTTPHost.String()},
			SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		}),
	)

	// JavaScript SPA frontend
	frontend := router.Group("/")
	frontend.Use(static.Serve("/", static.LocalFile(config.StaticAssetsDir, false)))

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
	private.POST("/devices", handlers.NewDeviceHandler)
	private.POST("/devices/:device_id", handlers.RekeyDeviceHandler)
	private.DELETE("/devices/:device_id", handlers.DeleteDeviceHandler)
	private.GET("/devices", handlers.ListUserDevicesHandler)

	// User Profile
	private.GET("/me", handlers.UserProfileInfoHandler)
	return router
}
