package wireguardhttps

import (
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/gin-gonic/gin"
)

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