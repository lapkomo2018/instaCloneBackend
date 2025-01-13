package v1

import (
	"log"

	"instaCloneBackend/internal/service"

	"github.com/labstack/echo/v4"
)

type (
	Handler struct {
		userService *service.User
		authService *service.Auth
	}

	Opts struct {
		UserService *service.User
		AuthService *service.Auth
	}
)

func New(opts Opts) *Handler {
	return &Handler{
		userService: opts.UserService,
		authService: opts.AuthService,
	}
}

func (h *Handler) Init(group *echo.Group) {
	log.Println("Initializing V1 api")
	h.initAuthRoutes(group.Group("/auth"))
}
