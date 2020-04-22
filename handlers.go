package wireguardhttps

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/markbates/goth/gothic"
)

type WireguardHandlers struct {
	config *ServerConfig
}

func (wh *WireguardHandlers) oauthCallbackHandler(c *gin.Context) {
	gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		// TODO: Error message
		c.Status(401)
		return
	}

	user, err := wh.config.Database.RegisterUser(
		gothUser.Name,
		gothUser.Email,
		gothUser.UserID,
		gothUser.Provider,
	)

	if err != nil {
		// TODO: HTTP handler for error type.
		c.Status(500)
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
		// TODO: HTTP handler for error type.
		c.Status(500)
		return
	}

	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) logoutHandler(c *gin.Context) {
	gothic.Logout(c.Writer, c.Request)
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
	router := gin.Default()
	handlers := &WireguardHandlers{config: config}
	// Authentication
	router.GET("/auth/callback", handlers.oauthCallbackHandler)
	router.GET("/auth/authenticate", handlers.authenticateHandler)
	router.GET("/auth/logout", handlers.logoutHandler)

	private := router.Group("/")
	private.Use(AuthRequiredMiddleware)

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
