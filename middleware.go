package wireguardhttps

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

func ProviderWhitelistMiddleware(c *gin.Context) {
	if !isAllowedProvider(c) {
		c.AbortWithStatus(http.StatusBadRequest)
	}

	c.Next()
}

func isAllowedProvider(c *gin.Context) bool {
	if p, err := gothic.GetProviderName(c.Request); err == nil {
		for _, provider := range goth.GetProviders() {
			if p == provider.Name() {
				return true
			}
		}
	}

	return false
}

func AuthenticationRequiredMiddleware(store sessions.Store, sessionName string) func(*gin.Context) {
	return func(c *gin.Context) {
		session, err := store.Get(c.Request, sessionName)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}

		user, ok := session.Values["user"]
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.Set("user", user)
		c.Next()
	}
}
