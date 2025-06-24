package test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Adachi324/oin/router"

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
	Username string `json:"username"  description:"用户名"`
	Password string `query:"password" description:"密码"`
}

type TestResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    TestRequest `json:"data"`
}

func Handler(c *gin.Context, req TestRequest) {

	var resp TestResponse
	resp.Code = 200
	resp.Message = "success"
	resp.Data = req
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

type Gender int

const (
	GenderUnknown Gender = 0
	GenderMale    Gender = 1
	GenderFemale  Gender = 2
)

func (g Gender) Enums() map[string]any {
	return map[string]any{
		"unknown": GenderUnknown,
		"male":    GenderMale,
		"female":  GenderFemale,
		"trans":   "trans",
	}
}

type ExampleReqVo struct {
	ID     int    `json:"id" binding:"required" description:"一个ID"`
	Name   string `query:"name" description:"一个名字"`
	Gender Gender `json:"gender" description:"一个性别"`
}

type ExampleRespVo struct {
	ID     int    `json:"id" binding:"required"`
	Name   string `json:"name" binding:"required"`
	Gender Gender `json:"gender" binding:"required"`
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
	engine.POST("/ex", router.New(
		ExampleHandler,
		router.Responses(router.Response{
			"200": router.ResponseItem{
				Description: "success",
				Model:       Response[ExampleRespVo]{},
				Headers:     nil,
			},
		}),
		router.Description("一个示例请求"),
		router.Summary("一个示例summary"),
		router.OperationID("example operation id"),
		router.Deprecated(),
	))
	engine.Run(":8082")
}
func ExampleHandler(c *gin.Context, reqVo ExampleReqVo) {
	c.JSON(200, ExampleRespVo{
		ID:     reqVo.ID,
		Name:   reqVo.Name,
		Gender: reqVo.Gender,
	})
}
func TestServeHTTP(t *testing.T) {
	engine := oin.New(newOpenapi())
	engine.POST("/test1/test2/dsads", router.New(
		Handler,
		router.Responses(router.Response{"200": router.ResponseItem{
			Description: "Test api response",
			Model:       Response[TestResponse]{},
			Headers:     nil,
		}})))

	engine.Engine.Use(func(c *gin.Context) {
		fmt.Println("test_gin_middleware")
		c.Next()
	})

	engine.Engine.GET("/test_gin", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})
	err := http.ListenAndServe(":8081", engine)
	if err != nil {
		t.Fatal(err)
	}
}
