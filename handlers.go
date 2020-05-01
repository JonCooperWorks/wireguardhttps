package wireguardhttps

import (
	"context"
	"encoding/gob"
	"log"
	"net"
	"net/http"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
)

type WireguardHandlers struct {
	config *ServerConfig
}

func (wh *WireguardHandlers) user(c *gin.Context) UserProfile {
	user, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	return *user.(*UserProfile)
}

func (wh *WireguardHandlers) storeUserInSession(c *gin.Context, user UserProfile) error {
	store := wh.config.SessionStore
	session, err := store.Get(c.Request, wh.config.SessionName)
	if err != nil {
		return err
	}
	session.Values["user"] = user
	return session.Save(c.Request, c.Writer)
}

func (wh *WireguardHandlers) oauthCallbackHandler(c *gin.Context) {
	gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	user, err := wh.config.Database.RegisterUser(
		gothUser.Name,
		gothUser.Email,
		gothUser.UserID,
		gothUser.Provider,
	)

	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	err = wh.storeUserInSession(c, user)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) authenticateHandler(c *gin.Context) {
	gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		gothic.BeginAuthHandler(c.Writer, c.Request)
		return
	}

	user, err := wh.config.Database.RegisterUser(
		gothUser.Name,
		gothUser.Email,
		gothUser.UserID,
		gothUser.Provider,
	)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	err = wh.storeUserInSession(c, user)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) logoutHandler(c *gin.Context) {
	err := gothic.Logout(c.Writer, c.Request)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func (wh *WireguardHandlers) newDeviceHandler(c *gin.Context) {
	client := wh.config.WireguardClient
	// TODO: Set to assigned device IP
	_, network, _ := net.ParseCIDR("10.0.0.0/24")
	credentials, err := client.CreatePeer(context.Background(), []net.IPNet{*network})
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	// TODO: Configure from JSON body
	_, err = wh.config.Database.CreateDevice(wh.user(c), "Macbook", "macOS", credentials.PublicKey)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
	}

	// TODO: Return generated INI template
	c.JSON(http.StatusOK, wh.user(c))

}

func (wh *WireguardHandlers) rekeyDeviceHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) listUserDevicesHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) getUserDeviceHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) userProfileInfoHandler(c *gin.Context) {
	user := wh.user(c)
	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) deleteDeviceHandler(c *gin.Context) {

}

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
	router.Use(adapter.Wrap(nosurf.NewPure))

	handlers := &WireguardHandlers{config: config}

	// Authentication
	auth := router.Group("/")
	auth.Use(ProviderWhitelistMiddleware)
	auth.GET("/auth/callback", handlers.oauthCallbackHandler)
	auth.GET("/auth/authenticate", handlers.authenticateHandler)
	auth.GET("/auth/logout", handlers.logoutHandler)

	// Private routes
	private := router.Group("/")
	private.Use(AuthenticationRequiredMiddleware(config.SessionStore, config.SessionName))

	// Devices
	private.POST("/devices", handlers.newDeviceHandler)
	private.POST("/devices/:device_id", handlers.rekeyDeviceHandler)
	private.DELETE("/devices/:device_id", handlers.deleteDeviceHandler)
	private.GET("/devices", handlers.listUserDevicesHandler)
	private.GET("/devices/:device_id", handlers.getUserDeviceHandler)

	// User Profile
	private.GET("/me", handlers.userProfileInfoHandler)
	return router
}
