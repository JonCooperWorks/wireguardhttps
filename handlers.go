package wireguardhttps

import (
	"github.com/gin-gonic/gin"
)

func Router(config *ServerConfig) *gin.Engine {
	router := gin.Default()
	return router
}
