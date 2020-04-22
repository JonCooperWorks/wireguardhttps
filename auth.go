package wireguardhttps

import (
	"github.com/gin-gonic/gin"
)

func AuthRequiredMiddleware(c *gin.Context) {
	// TODO: check validity of session token
	c.Next()
}