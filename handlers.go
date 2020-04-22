package wireguardhttps

import (
	"github.com/gin-gonic/gin"
)

type WireguardHandler struct {
	config *ServerConfig
}

func Router(config *ServerConfig) *gin.Engine {
	router := gin.Default()
	return router
}
