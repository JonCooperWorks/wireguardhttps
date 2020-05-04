package wireguardhttps

import (
	"encoding/gob"

	"github.com/markbates/goth"
	"github.com/gin-contrib/secure"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
	"github.com/gin-gonic/gin"
)


func Router(config *ServerConfig) *gin.Engine {
	goth.UseProviders(config.AuthProviders...)
	gob.Register(&UserProfile{})
	router := gin.Default()
	router.Use(secure.New(
		secure.Config{
			BrowserXssFilter: true,
			IENoOpen:         true,
			FrameDeny:        true,
			AllowedHosts:     []string{config.HTTPHost.Hostname()},
			SSLRedirect:      true,
			IsDevelopment:    config.IsDebug,
		}),
	)
	if !config.IsDebug {
		router.Use(adapter.Wrap(nosurf.NewPure))
	}

	handlers := &WireguardHandlers{config: config}

	// Authentication
	auth := router.Group("/auth")
	auth.Use(ProviderWhitelistMiddleware)
	auth.GET("/callback", handlers.OauthCallbackHandler)
	auth.GET("/authenticate", handlers.AuthenticateHandler)
	auth.GET("/logout", handlers.LogoutHandler)

	// Private routes
	private := router.Group("/")
	private.Use(AuthenticationRequiredMiddleware(config.SessionStore, config.SessionName))

	// Devices
	private.POST("/devices", handlers.NewDeviceHandler)
	private.POST("/devices/:device_id", handlers.RekeyDeviceHandler)
	private.DELETE("/devices/:device_id", handlers.DeleteDeviceHandler)
	private.GET("/devices", handlers.ListUserDevicesHandler)
	private.GET("/devices/:device_id", handlers.GetUserDeviceHandler)

	// User Profile
	private.GET("/me", handlers.UserProfileInfoHandler)
	return router
}
