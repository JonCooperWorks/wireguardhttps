package wireguardhttps

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/joncooperworks/wgrpcd"
	"github.com/markbates/goth/gothic"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardHandlers struct {
	*ServerConfig
}

func (wh *WireguardHandlers) respondToError(c *gin.Context, err error) {
	log.Println(err)
	if _, ok := err.(*RecordNotFoundError); ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.AbortWithStatus(http.StatusInternalServerError)
}

func (wh *WireguardHandlers) user(c *gin.Context) UserProfile {
	user, ok := c.Get("user")
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	return *user.(*UserProfile)
}

func (wh *WireguardHandlers) storeUserInSession(c *gin.Context, user UserProfile) error {
	store := wh.SessionStore
	session, err := store.Get(c.Request, wh.SessionName)
	if err != nil {
		return err
	}
	session.Values["user"] = user
	return session.Save(c.Request, c.Writer)
}

func (wh *WireguardHandlers) OAuthCallbackHandler(c *gin.Context) {
	gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	user, err := wh.Database.RegisterUser(
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
		return
	}

	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) AuthenticateHandler(c *gin.Context) {
	gothUser, err := gothic.CompleteUserAuth(c.Writer, c.Request)
	if err != nil {
		// Patch in single tenant support
		url, err := gothic.GetAuthURL(c.Writer, c.Request)
		if err != nil {
			log.Println(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		url = strings.Replace(url, "common", wh.ADTenantName, -1)
		c.Redirect(http.StatusTemporaryRedirect, url)
		return
	}

	user, err := wh.Database.RegisterUser(
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
		return
	}
	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) LogoutHandler(c *gin.Context) {
	err := gothic.Logout(c.Writer, c.Request)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func (wh *WireguardHandlers) NewDeviceHandler(c *gin.Context) {
	var deviceRequest DeviceRequest
	err := c.BindJSON(&deviceRequest)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	deviceFunc := func(ipAddress IPAddress) (*wgrpcd.PeerConfigInfo, error) {
		_, network, err := net.ParseCIDR(fmt.Sprintf("%v/32", ipAddress.Address))
		if err != nil {
			return nil, err
		}

		credentials, err := wh.WireguardClient.CreatePeer(context.Background(), []net.IPNet{*network})
		if err != nil {
			return nil, err
		}

		return credentials, nil
	}
	_, credentials, err := wh.Database.CreateDevice(wh.user(c), deviceRequest.Name, deviceRequest.OS, deviceFunc)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	tmpl, ok := wh.Templates["peer_config"]
	if !ok {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	peerConfigINI := &PeerConfigINI{
		PublicKey:  credentials.ServerPublicKey,
		PrivateKey: credentials.PrivateKey,
		AllowedIPs: wgrpcd.IPNetsToStrings(credentials.AllowedIPs),
		Addresses:  wgrpcd.IPNetsToStrings(credentials.AllowedIPs),
		ServerName: wh.Endpoint.String(),
		DNSServers: wgrpcd.IPsToStrings(wh.DNSServers),
	}
	buffer := &bytes.Buffer{}
	err = tmpl.Execute(buffer, peerConfigINI)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, "text/plain", buffer.Bytes())
	buffer.Reset()
}

func (wh *WireguardHandlers) RekeyDeviceHandler(c *gin.Context) {
	user := wh.user(c)
	deviceID, err := strconv.Atoi(c.Param("device_id"))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	device, err := wh.Database.Device(user, deviceID)
	if err != nil {
		wh.respondToError(c, err)
		return
	}

	rekeyFunc := func(ipAddress IPAddress) (*wgrpcd.PeerConfigInfo, error) {
		_, network, err := net.ParseCIDR(fmt.Sprintf("%v/32", ipAddress.Address))
		if err != nil {
			return nil, err
		}

		publicKey, err := wgtypes.ParseKey(device.PublicKey)
		if err != nil {
			return nil, err
		}
		credentials, err := wh.WireguardClient.RekeyPeer(context.Background(), publicKey, []net.IPNet{*network})
		if err != nil {
			return nil, err
		}

		return credentials, nil
	}
	_, credentials, err := wh.Database.RekeyDevice(wh.user(c), device, rekeyFunc)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	tmpl, ok := wh.Templates["peer_config"]
	if !ok {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	peerConfigINI := &PeerConfigINI{
		PublicKey:  credentials.ServerPublicKey,
		PrivateKey: credentials.PrivateKey,
		AllowedIPs: wgrpcd.IPNetsToStrings(credentials.AllowedIPs),
		Addresses:  wgrpcd.IPNetsToStrings(credentials.AllowedIPs),
		ServerName: wh.Endpoint.String(),
		DNSServers: wgrpcd.IPsToStrings(wh.DNSServers),
	}
	buffer := &bytes.Buffer{}
	err = tmpl.Execute(buffer, peerConfigINI)
	if err != nil {
		log.Println(err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.Header("Cache-Control", "no-cache")
	c.Data(http.StatusOK, "text/plain", buffer.Bytes())
	buffer.Reset()
}

func (wh *WireguardHandlers) ListUserDevicesHandler(c *gin.Context) {
	devices, err := wh.Database.Devices(wh.user(c))
	if err != nil {
		wh.respondToError(c, err)
		return
	}

	c.JSON(http.StatusOK, devices)
}

func (wh *WireguardHandlers) UserProfileInfoHandler(c *gin.Context) {
	user := wh.user(c)
	c.JSON(http.StatusOK, user)
}

func (wh *WireguardHandlers) DeleteDeviceHandler(c *gin.Context) {
	user := wh.user(c)
	deviceID, err := strconv.Atoi(c.Param("device_id"))
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	device, err := wh.Database.Device(user, deviceID)
	if err != nil {
		wh.respondToError(c, err)
		return
	}

	deleteFunc := func() error {
		publicKey, err := wgtypes.ParseKey(device.PublicKey)
		if err != nil {
			return err
		}
		_, err = wh.WireguardClient.RemovePeer(context.Background(), publicKey)
		if err != nil {
			return err
		}

		return nil
	}
	err = wh.Database.RemoveDevice(wh.user(c), device, deleteFunc)
	if err != nil {
		wh.respondToError(c, err)
		return
	}

	c.AbortWithStatus(http.StatusNoContent)
}
