package wireguardhttps

import (
	"log"

	"github.com/gin-gonic/gin"
)

func AuthRequiredMiddleware(c *gin.Context) {
	// TODO: check validity of session token and put UserProfile on the gin.Context.
	log.Println("Checking authentications")
	c.Next()
}