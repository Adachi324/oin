package oin

import (
	"net/http"
	urlpath "path"
	"strings"

	"github.com/Adachi324/oin/router"
	"github.com/Adachi324/oin/security"
	"github.com/gin-gonic/gin"
)

type Group struct {
	*Oin
	RouterGroup *gin.RouterGroup
	Path        string
	Tags        []string
	Handlers    []gin.HandlerFunc
	Securities  []security.ISecurity
}

type Option func(*Group)

func Handlers(handlers ...gin.HandlerFunc) Option {
	return func(g *Group) {
		g.Handlers = append(g.Handlers, handlers...)
	}
}

func Tags(tags ...string) Option {
	return func(g *Group) {
		if g.Tags == nil {
			g.Tags = tags
		} else {
			g.Tags = append(g.Tags, tags...)
		}
	}
}

func Security(securities ...security.ISecurity) Option {
	return func(g *Group) {
		g.Securities = append(g.Securities, securities...)
	}
}

func (g *Group) Use(middleware ...gin.HandlerFunc) gin.IRoutes {
	return g.RouterGroup.Use(middleware...)
}

func (g *Group) Handle(path string, method string, r *router.Router) {
	router.Handlers(g.Handlers...)(r)
	router.Tags(g.Tags...)(r)
	router.Security(g.Securities...)(r)
	g.setRouterDefault(path, method, r)
	g.Oin.Handle(g.RouterGroup, urlpath.Join(g.Path, path), method, r)
}

func (g *Group) GET(path string, router *router.Router) {
	g.Handle(path, http.MethodGet, router)
}

func (g *Group) POST(path string, router *router.Router) {
	g.Handle(path, http.MethodPost, router)
}

func (g *Group) HEAD(path string, router *router.Router) {
	g.Handle(path, http.MethodHead, router)
}

func (g *Group) PATCH(path string, router *router.Router) {
	g.Handle(path, http.MethodPatch, router)
}

func (g *Group) DELETE(path string, router *router.Router) {
	g.Handle(path, http.MethodDelete, router)
}

func (g *Group) PUT(path string, router *router.Router) {
	g.Handle(path, http.MethodPut, router)
}

func (g *Group) OPTIONS(path string, router *router.Router) {
	g.Handle(path, http.MethodOptions, router)
}

func (g *Group) Group(path string, options ...Option) *Group {
	group := &Group{
		Oin:         g.Oin,
		RouterGroup: g.RouterGroup.Group(""),
		Path:        urlpath.Join(g.Path, path),
		Tags:        g.Tags,
		Handlers:    g.Handlers,
		Securities:  g.Securities,
	}
	for _, option := range options {
		option(group)
	}
	return group
}

func (g *Group) setRouterDefault(path, method string, r *router.Router) {
	defaultSummary := strings.TrimPrefix(path, "/")
	defaultSummary = strings.ReplaceAll(defaultSummary, "_", " ")
	defaultSummary = defaultSummary + " " + strings.ToLower(method)

	if len(r.Summary) == 0 {
		router.Summary(defaultSummary)(r)
	}

	if len(r.Description) == 0 {
		router.Description(defaultSummary)(r)
	}

	if r.ErrorHandler == nil {
		router.ErrorHandler(g.ErrorHandler)(r)
	}
}
