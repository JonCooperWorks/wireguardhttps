package wireguardhttps

import (
	"log"
	
	"github.com/gin-gonic/gin"
)

func AuthRequiredMiddleware(c *gin.Context) {
	// TODO: check validity of session token
	log.Println("Checking authentications")
	c.Next()
}