package openapi

import (
	"github.com/Adachi324/oin/router"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
)

type Option func(openapi *Openapi)

func Routers(routers map[*gin.RouterGroup]map[string]map[string]*router.Router) Option {
	return func(openapi *Openapi) {
		openapi.Routers = routers
	}
}

func DocsUrl(url string) Option {
	return func(openapi *Openapi) {
		openapi.DocsUrl = url
	}
}

func RedocUrl(url string) Option {
	return func(openapi *Openapi) {
		openapi.RedocUrl = url
	}
}

func Title(title string) Option {
	return func(openapi *Openapi) {
		openapi.Title = title
	}
}

func Description(description string) Option {
	return func(openapi *Openapi) {
		openapi.Description = description
	}
}

func Version(version string) Option {
	return func(openapi *Openapi) {
		openapi.Version = version
	}
}

func OpenAPIUrl(url string) Option {
	return func(openapi *Openapi) {
		openapi.OpenAPIUrl = url
	}
}

func Servers(servers openapi3.Servers) Option {
	return func(openapi *Openapi) {
		openapi.Servers = servers
	}
}

func TermsOfService(TermsOfService string) Option {
	return func(openapi *Openapi) {
		openapi.TermsOfService = TermsOfService
	}
}

func Contact(Contact *openapi3.Contact) Option {
	return func(openapi *Openapi) {
		openapi.Contact = Contact
	}
}

func License(License *openapi3.License) Option {
	return func(openapi *Openapi) {
		openapi.License = License
	}
}

func OpenapiOptions(options map[string]any) Option {
	return func(openapi *Openapi) {
		openapi.OpenapiOptions = options
	}
}

func RedocOptions(options map[string]any) Option {
	return func(openapi *Openapi) {
		openapi.RedocOptions = options
	}
}

// DisableDocs 禁用文档端点（生产环境推荐）
func DisableDocs() Option {
	return func(openapi *Openapi) {
		openapi.DocsEnabled = false
	}
}

// EnableDocs 启用文档端点
func EnableDocs() Option {
	return func(openapi *Openapi) {
		openapi.DocsEnabled = true
	}
}

// DocsMiddleware 为文档端点添加中间件（例如身份验证）
func DocsMiddleware(middleware ...gin.HandlerFunc) Option {
	return func(openapi *Openapi) {
		openapi.DocsMiddleware = middleware
	}
}
