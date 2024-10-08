package router

import (
	"container/list"
	"fmt"
	"log"
	"net/http"
	"reflect"

	"github.com/Adachi324/oin/security"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/jinzhu/copier"
	"github.com/mcuadros/go-defaults"
)

type Model any
type ErrorHandlerFunc func(ctx *gin.Context, err error, status int)

type Router struct {
	Handlers            *list.List
	Path                string
	Method              string
	Summary             string
	Description         string
	Deprecated          bool
	RequestContentType  string
	ResponseContentType string
	Tags                []string
	API                 gin.HandlerFunc
	Model               Model
	OperationID         string
	Exclude             bool
	Securities          []security.ISecurity
	Response            Response
	ErrorHandler        ErrorHandlerFunc
}

var Validate = validator.New()

func (router *Router) BindModel(req any) gin.HandlerFunc {
	return func(c *gin.Context) {
		bindErr := func() (err error) {
			model := reflect.New(reflect.TypeOf(req).Elem()).Interface()
			if err = c.ShouldBindHeader(model); err != nil {
				return
			}

			if err = CookiesParser(c, model); err != nil {
				return
			}

			if err = c.ShouldBindWith(model, Query); err != nil {
				return
			}

			if c.Request.Method == http.MethodPost || c.Request.Method == http.MethodPut {
				switch c.Request.Header.Get("Content-Type") {
				case binding.MIMEMultipartPOSTForm:
					if err = c.ShouldBindWith(model, binding.FormMultipart); err != nil {
						return
					}
				case binding.MIMEJSON:
					if err = c.ShouldBindWith(model, binding.JSON); err != nil {
						return
					}
				case binding.MIMEXML:
					if err = c.ShouldBindWith(model, binding.XML); err != nil {
						return
					}
				case binding.MIMEPOSTForm:
					if err = c.ShouldBindWith(model, binding.Form); err != nil {
						return
					}
				case binding.MIMEYAML:
					if err = c.ShouldBindWith(model, binding.YAML); err != nil {
						return
					}
				case binding.MIMEPROTOBUF:
					if err = c.ShouldBindWith(model, binding.ProtoBuf); err != nil {
						return
					}
				case binding.MIMEMSGPACK:
					if err = c.ShouldBindWith(model, binding.MsgPack); err != nil {
						return
					}
				}
			}

			if err = c.ShouldBindUri(model); err != nil {
				return
			}

			defaults.SetDefaults(model)
			defer func() {
				if rec := recover(); rec != nil {
					err = fmt.Errorf("%v", rec)
				}
			}()

			if err = Validate.Struct(model); err != nil {
				return err
			}

			if err = copier.Copy(req, model); err != nil {
				return err
			}

			return nil
		}()

		if bindErr != nil {
			if router.ErrorHandler != nil {
				router.ErrorHandler(c, bindErr, http.StatusBadRequest)
				c.Abort()
			} else {
				log.Panic(bindErr)
			}
		}

		c.Next()
	}
}

func (router *Router) GetHandlers() []gin.HandlerFunc {
	var handlers []gin.HandlerFunc
	for _, s := range router.Securities {
		handlers = append(handlers, s.Authorize)
	}
	for h := router.Handlers.Front(); h != nil; h = h.Next() {
		if f, ok := h.Value.(gin.HandlerFunc); ok {
			handlers = append(handlers, f)
		}
	}
	handlers = append(handlers, router.API)
	return handlers
}

func NewX(f gin.HandlerFunc, options ...Option) *Router {
	r := &Router{
		Handlers: list.New(),
		Response: make(Response),
		API: func(ctx *gin.Context) {
			f(ctx)
		},
	}
	for _, option := range options {
		option(r)
	}
	return r
}

func New[T Model, F func(c *gin.Context, req T)](f F, options ...Option) *Router {
	var model T

	r := &Router{
		Handlers: list.New(),
		Response: make(Response),
		API: func(ctx *gin.Context) {
			f(ctx, model)
		},
		Model:               model,
		RequestContentType:  "application/json",
		ResponseContentType: "application/json",
	}

	for _, option := range options {
		option(r)
	}

	r.Handlers.PushBack(r.BindModel(&model))
	return r
}

func (router *Router) WithSecurity(securities ...security.ISecurity) *Router {
	Security(securities...)(router)
	return router
}

func (router *Router) WithResponses(response Response) *Router {
	Responses(response)(router)
	return router
}

func (router *Router) WithHandlers(handlers ...gin.HandlerFunc) *Router {
	Handlers(handlers...)(router)
	return router
}

func (router *Router) WithTags(tags ...string) *Router {
	Tags(tags...)(router)
	return router
}

func (router *Router) WithSummary(summary string) *Router {
	Summary(summary)(router)
	return router
}

func (router *Router) WithDescription(description string) *Router {
	Description(description)(router)
	return router
}

func (router *Router) WithDeprecated() *Router {
	Deprecated()(router)
	return router
}

func (router *Router) WithOperationID(ID string) *Router {
	OperationID(ID)(router)
	return router
}

func (router *Router) WithExclude() *Router {
	Exclude()(router)
	return router
}

func (router *Router) WithContentType(contentType string, contentTypeType ContentTypeType) *Router {
	ContentType(contentType, contentTypeType)(router)
	return router
}
