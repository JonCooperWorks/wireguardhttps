package wireguardhttps

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/gin-contrib/secure"
	"github.com/gin-gonic/gin"
	"github.com/gwatts/gin-adapter"
	"github.com/joncooperworks/wgrpcd"
	"github.com/justinas/nosurf"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
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
	var deviceRequest DeviceRequest
	err := c.BindJSON(&deviceRequest)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	client := wh.config.WireguardClient
	deviceFunc := func(ipAddress IPAddress) (*wgrpcd.PeerConfigInfo, error) {
		_, network, err := net.ParseCIDR(fmt.Sprintf("%v/32", ipAddress.Address))
		if err != nil {
			return nil, err
		}

		credentials, err := client.CreatePeer(context.Background(), []net.IPNet{*network})
		if err != nil {
			return nil, err
		}

		return credentials, nil
	}
	_, credentials, err := wh.config.Database.CreateDevice(wh.user(c), deviceRequest.Name, deviceRequest.OS, deviceFunc)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	tmpl := template.Must(
		template.New("peerconfig.tmpl").
			Funcs(map[string]interface{}{"StringsJoin": strings.Join}).
			ParseFiles(filepath.Join(wh.config.TemplatesDirectory, "ini/peerconfig.tmpl")),
	)

	peerConfigINI := &PeerConfigINI{
		PublicKey:  credentials.ServerPublicKey,
		PrivateKey: credentials.PrivateKey,
		AllowedIPs: ipNetsToStrings(credentials.AllowedIPs),
		Addresses:  ipNetsToStrings(credentials.AllowedIPs),
		ServerName: wh.config.Endpoint.String(),
		DNSServers: ipsToStrings(wh.config.DNSServers),
	}
	buffer := &bytes.Buffer{}
	err = tmpl.Execute(buffer, peerConfigINI)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Data(http.StatusOK, "text/plain", buffer.Bytes())

}

func (wh *WireguardHandlers) rekeyDeviceHandler(c *gin.Context) {

}

func (wh *WireguardHandlers) listUserDevicesHandler(c *gin.Context) {
	devices, err := wh.config.Database.Devices(wh.user(c))
	if err != nil {
		log.Println(err)
		if _, ok := err.(*RecordNotFoundError); ok {
			c.AbortWithStatus(http.StatusNotFound)
		}
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, devices)
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
	if !config.IsDebug {
		router.Use(adapter.Wrap(nosurf.NewPure))
	}

	handlers := &WireguardHandlers{config: config}

	// Authentication
	auth := router.Group("/auth")
	auth.Use(ProviderWhitelistMiddleware)
	auth.GET("/callback", handlers.oauthCallbackHandler)
	auth.GET("/authenticate", handlers.authenticateHandler)
	auth.GET("/logout", handlers.logoutHandler)

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
