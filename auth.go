package wireguardhttps

import (
	"log"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/gin-gonic/gin"
)

func AuthRequiredMiddleware(c *gin.Context) {
	// TODO: check validity of session token and put UserProfile on the gin.Context.
	log.Println("Checking authentications")
	c.Next()
}

func ProviderWhitelistMiddleware(c *gin.Context) {
	if !isAllowedProvider(c) {
		c.AbortWithStatus(401)
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