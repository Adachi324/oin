package router

import (
	"net/http"
	_ "unsafe"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
)

var Query = queryBinding{}

func CookiesParser(c *gin.Context, model any) error {
	params := make(map[string][]string)
	for _, cookie := range c.Request.Cookies() {
		params[cookie.Name] = append(params[cookie.Name], cookie.Value)
	}
	return copier.Copy(model, params)
}

type queryBinding struct{}

func (queryBinding) Name() string {
	return "query"
}

//go:linkname mapFormByTag github.com/gin-gonic/gin/binding.mapFormByTag
func mapFormByTag(ptr any, form map[string][]string, tag string) error

func (queryBinding) Bind(req *http.Request, obj any) error {
	values := req.URL.Query()
	if err := mapFormByTag(obj, values, "query"); err != nil {
		return err
	}
	return nil
}
