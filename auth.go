package wireguardhttps

func AuthRequiredMiddleware(c *gin.Context) {
	// TODO: check validity of session token
	c.Next()
}