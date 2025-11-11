package oin

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	urlpath "path"
	"strings"
	"sync"

	"github.com/Adachi324/oin/openapi"
	"github.com/Adachi324/oin/router"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var templates embed.FS

type Oin struct {
	*gin.Engine
	RouterGroup    *gin.RouterGroup
	Openapi        *openapi.Openapi
	Routers        map[*gin.RouterGroup]map[string]map[string]*router.Router
	subApps        map[string]*Oin
	rootPath       string
	ErrorHandler   router.ErrorHandlerFunc
	beforeInitFunc func()
	afterInitFunc  func()
	initOnce       sync.Once
}

func NewWithEngine(openapi *openapi.Openapi, g *gin.Engine) *Oin {
	f := &Oin{
		Engine:      g,
		RouterGroup: g.Group(""),
		Openapi:     openapi,
		Routers:     make(map[*gin.RouterGroup]map[string]map[string]*router.Router),
		subApps:     make(map[string]*Oin),
	}

	f.SetHTMLTemplate(template.Must(template.ParseFS(templates, "templates/*.html")))
	if openapi != nil {
		openapi.Routers = f.Routers
	}
	return f
}

func New(openapi *openapi.Openapi) *Oin {
	engine := gin.New()
	f := &Oin{
		Engine:      engine,
		RouterGroup: engine.Group(""),
		Openapi:     openapi,
		Routers:     make(map[*gin.RouterGroup]map[string]map[string]*router.Router),
		subApps:     make(map[string]*Oin),
	}

	f.SetHTMLTemplate(template.Must(template.ParseFS(templates, "templates/*.html")))
	if openapi != nil {
		openapi.Routers = f.Routers
	}
	return f
}

func (g *Oin) WithErrorHandler(handler router.ErrorHandlerFunc) *Oin {
	g.ErrorHandler = handler
	return g
}

func (g *Oin) SetRootPath(path string) {
	g.rootPath = path
}

func (g *Oin) Mount(path string, app *Oin) {
	app.rootPath = path
	app.Engine = g.Engine
	if app.ErrorHandler == nil {
		app.ErrorHandler = g.ErrorHandler
	}
	app.Openapi.Servers = append(app.Openapi.Servers, &openapi3.Server{
		URL: path,
	})
	g.subApps[path] = app
}

func (g *Oin) Use(middleware ...gin.HandlerFunc) gin.IRoutes {
	return g.RouterGroup.Use(middleware...)
}

func (g *Oin) Group(path string, options ...Option) *Group {
	group := &Group{
		Oin:         g,
		RouterGroup: g.RouterGroup.Group(""),
		Path:        path,
	}

	for _, option := range options {
		option(group)
	}
	return group
}

func (g *Oin) Handle(group *gin.RouterGroup, path string, method string, r *router.Router) {

	r.Method = method
	r.Path = path

	if g.Routers[group] == nil {
		g.Routers[group] = make(map[string]map[string]*router.Router)
	}

	if g.Routers[group][path] == nil {
		g.Routers[group][path] = make(map[string]*router.Router)
	}

	g.Routers[group][path][method] = r
}

func (g *Oin) handle(path string, method string, r *router.Router) {
	g.Handle(g.RouterGroup, path, method, r)
}

func (g *Oin) GET(path string, router *router.Router) {
	g.handle(path, http.MethodGet, router)
}

func (g *Oin) POST(path string, router *router.Router) {
	g.handle(path, http.MethodPost, router)
}

func (g *Oin) HEAD(path string, router *router.Router) {
	g.handle(path, http.MethodHead, router)
}

func (g *Oin) PATCH(path string, router *router.Router) {
	g.handle(path, http.MethodPatch, router)
}

func (g *Oin) DELETE(path string, router *router.Router) {
	g.handle(path, http.MethodDelete, router)
}

func (g *Oin) PUT(path string, router *router.Router) {
	g.handle(path, http.MethodPut, router)
}

func (g *Oin) OPTIONS(path string, router *router.Router) {
	g.handle(path, http.MethodOptions, router)
}

func (g *Oin) Any(path string, router *router.Router) {
	var anyMethods = []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodHead, http.MethodOptions, http.MethodDelete, http.MethodConnect,
		http.MethodTrace,
	}

	for _, method := range anyMethods {
		g.handle(path, method, router)
	}
}

func (g *Oin) init() {
	g.initRouters()
	if g.Openapi == nil {
		return
	}
	gin.DisableBindValidation()

	// 检查是否启用文档
	if !g.Openapi.DocsEnabled {
		g.Openapi.BuildOpenAPI()
		return
	}

	openAPIHandler := func(c *gin.Context) {
		if strings.HasSuffix(g.Openapi.OpenAPIUrl, ".yml") ||
			strings.HasSuffix(g.Openapi.OpenAPIUrl, ".yaml") {
			y, err := g.Openapi.MarshalYAML()
			if err != nil {
				c.JSON(http.StatusInternalServerError, map[string]string{"status": err.Error()})
			}
			c.String(http.StatusOK, string(y))
		} else {
			c.JSON(http.StatusOK, g.Openapi)
		}
	}

	// 为 OpenAPI 端点应用中间件
	openAPIHandlers := append(g.Openapi.DocsMiddleware, openAPIHandler)
	g.Engine.GET(g.fullPath(g.Openapi.OpenAPIUrl), openAPIHandlers...)
	// Note: Docs 和 Redoc js 请求 openapi.json 的路径会多加一级 rootPath，不知道具体原因，这里做下适配
	if urlpath.Join(g.rootPath, g.fullPath(g.Openapi.OpenAPIUrl)) != g.fullPath(g.Openapi.OpenAPIUrl) {
		g.Engine.GET(urlpath.Join(g.rootPath, g.fullPath(g.Openapi.OpenAPIUrl)), openAPIHandlers...)
	}

	// 为 Swagger UI 应用中间件
	docsHandler := func(c *gin.Context) {
		options := `{}`
		if g.Openapi.OpenapiOptions != nil {
			data, err := json.Marshal(g.Openapi.OpenapiOptions)
			if err != nil {
				panic(err)
			}
			options = string(data)
		}
		c.HTML(http.StatusOK, "swagger.html", gin.H{
			"openapi_url":     g.fullPath(g.Openapi.OpenAPIUrl),
			"title":           g.Openapi.Title,
			"openapi_options": options,
		})
	}
	docsHandlers := append(g.Openapi.DocsMiddleware, docsHandler)
	g.Engine.GET(g.fullPath(g.Openapi.DocsUrl), docsHandlers...)

	// 为 Redoc 应用中间件
	redocHandler := func(c *gin.Context) {
		options := `{}`
		if g.Openapi.RedocOptions != nil {
			data, err := json.Marshal(g.Openapi.RedocOptions)
			if err != nil {
				panic(err)
			}
			options = string(data)
		}
		c.HTML(http.StatusOK, "redoc.html", gin.H{
			"openapi_url":   g.fullPath(g.Openapi.OpenAPIUrl),
			"title":         g.Openapi.Title,
			"redoc_options": options,
		})
	}
	redocHandlers := append(g.Openapi.DocsMiddleware, redocHandler)
	g.Engine.GET(g.fullPath(g.Openapi.RedocUrl), redocHandlers...)

	g.Openapi.BuildOpenAPI()
}

func (g *Oin) initRouters() {
	for group, routers := range g.Routers {
		for path, m := range routers {
			path = g.fullPath(path)
			for method, r := range m {
				handlers := r.GetHandlers()
				if method == http.MethodGet {
					group.GET(path, handlers...)
				} else if method == http.MethodPost {
					group.POST(path, handlers...)
				} else if method == http.MethodHead {
					group.HEAD(path, handlers...)
				} else if method == http.MethodPatch {
					group.PATCH(path, handlers...)
				} else if method == http.MethodDelete {
					group.DELETE(path, handlers...)
				} else if method == http.MethodPut {
					group.PUT(path, handlers...)
				} else if method == http.MethodOptions {
					group.OPTIONS(path, handlers...)
				} else {
					group.Any(path, handlers...)
				}
			}
		}
	}
}

func (g *Oin) Init() {
	g.initOnce.Do(func() {
		if g.beforeInitFunc != nil {
			g.beforeInitFunc()
		}
		g.init()
		for _, s := range g.subApps {
			s.init()
		}
		if g.afterInitFunc != nil {
			g.afterInitFunc()
		}
	})
}

func (g *Oin) fullPath(path string) string {
	return g.rootPath + path
}

func (g *Oin) BeforeInit(f func()) {
	g.beforeInitFunc = f
}

func (g *Oin) AfterInit(f func()) {
	g.afterInitFunc = f
}

func (g *Oin) Run(addr ...string) error {
	g.Init()
	return g.Engine.Run(addr...)
}

func (g *Oin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.Engine.ServeHTTP(w, r)
}

func (g *Oin) StartGraceful(addr ...string) (*http.Server, error) {
	g.Init()
	var address string
	if len(addr) == 0 {
		address = ":" + os.Getenv("PORT")
		if address == ":" {
			address = ":8080"
		}
	} else {
		address = addr[0]
	}
	server := &http.Server{
		Addr:    address,
		Handler: g.Engine,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("ERROR starting server: %v", err))
		}
	}()
	return server, nil
}
