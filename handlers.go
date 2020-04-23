package wireguardhttps

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type WireguardHandlers struct {
	config *ServerConfig
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
		c.AbortWithStatus(http.StatusInternalServerError)
		return
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

}

func (wh *WireguardHandlers) rekeyDeviceHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) listUserDevicesHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) getUserDeviceHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) userProfileInfoHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) deleteDeviceHandler(c *gin.Context) {

}

func Router(config *ServerConfig) *gin.Engine {
	goth.UseProviders(config.AuthProviders...)
	router := gin.Default()
	handlers := &WireguardHandlers{config: config}

	// Authentication
	auth := router.Group("/")
	auth.Use(ProviderWhitelistMiddleware)
	auth.GET("/auth/callback", handlers.oauthCallbackHandler)
	auth.GET("/auth/authenticate", handlers.authenticateHandler)
	auth.GET("/auth/logout", handlers.logoutHandler)

	// Private routes
	private := router.Group("/")

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
