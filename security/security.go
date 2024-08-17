package security

import (
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
)

const (
	Credentials = "credentials"
	BasicAuth   = "BasicAuth"
	BearerAuth  = "BearerAuth"
	ApiKeyAuth  = "ApiKeyAuth"
	OpenIDAuth  = "OpenIDAuth"
	OAuth2Auth  = "OAuth2Auth"
)

type ISecurity interface {
	Authorize(g *gin.Context)
	Callback(c *gin.Context, credentials any, err error)
	Provider() string
	Scheme() *openapi3.SecurityScheme
}

type Security struct {
	ISecurity
}

func (s *Security) Callback(c *gin.Context, credentials any, err error) {
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	} else {
		c.Set(Credentials, credentials)
	}
}
