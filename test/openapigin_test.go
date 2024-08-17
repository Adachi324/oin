package test

import (
	"github.com/Adachi324/oin/router"
	"testing"

	"github.com/Adachi324/oin"
	"github.com/Adachi324/oin/openapi"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
)

type Response[T any] struct {
	Code    int    `json:"code" form:"code" query:"code" validate:"required" example:"200" enums:"200,400,500"`
	Data    T      `json:"data" form:"data" query:"data"`
	Msg     string `json:"msg" form:"msg" query:"msg"`
	TraceID string `json:"trace_id" form:"trace_id" query:"trace_id" validate:"required"`
}

type TestRequest struct {
	Username string `json:"username" form:"username" query:"username"`
	Password string `json:"password" form:"password" query:"password"`
}

type TestResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func Handler(c *gin.Context, req TestRequest) {
	var resp TestResponse
	resp.Code = 200
	resp.Message = "success"
	c.JSON(200, resp)
}
func newOpenapi() *openapi.Openapi {

	return openapi.New(
		"Test openapi gin",
		"For test this package",
		"0.1.0",
		openapi.License(&openapi3.License{
			Name: "Apache License 2.0",
			URL:  "",
		}),
		openapi.Contact(&openapi3.Contact{
			Name:  "",
			URL:   "",
			Email: "",
		}),
		openapi.TermsOfService(""),
	)
}

func TestSwag(t *testing.T) {
	engine := oin.New(newOpenapi())
	//engine.Use(...)
	engine.POST("/test1/test2/dsads", router.New(
		Handler,
		router.Responses(router.Response{"200": router.ResponseItem{
			Description: "Test api response",
			Model:       Response[TestResponse]{},
			Headers:     nil,
		}})))
	engine.Run(":8081")
}
