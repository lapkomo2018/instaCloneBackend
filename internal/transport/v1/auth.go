package v1

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"instaCloneBackend/internal/model"

	"github.com/labstack/echo/v4"
	"github.com/markbates/goth/gothic"
)

const (
	AuthorizationHeaderKey = "Authorization"
	RefreshTokenCookieName = "Refresh-Token"
)

func (h *Handler) initAuthRoutes(group *echo.Group) {
	group.POST("/register", h.handlePostRegister)
	group.POST("/login", h.handlePostLogin)
	group.POST("/logout", h.handlePostLogout)
	group.POST("/logoutAll", h.handlePostLogoutAll, h.authMiddleware)
	group.POST("/refresh", h.handlePostRefresh)
	group.GET("/verify", h.handleGetVerify)
	group.POST("/forgot", h.handlePostForgot)
	group.POST("/reset", h.handlePostReset)
	group.GET("/:provider", h.handleGetProvider)
	group.GET("/:provider/callback", h.handleGetProviderCallback)
}

func (h *Handler) handlePostRegister(c echo.Context) error {
	var body struct {
		Username string `json:"username" validate:"required,min=3,max=32"`
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	verificationUrl := fmt.Sprintf("%s://%s%s/verify?token=", c.Scheme(), c.Request().Host, strings.TrimSuffix(c.Request().URL.Path, "/register"))
	user, err := h.authService.Register(c.Request().Context(), body.Username, body.Email, body.Password, verificationUrl)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusCreated, user)
}

func (h *Handler) handlePostLogin(c echo.Context) error {
	// Bind the request body to the struct
	var body struct {
		Login    string `json:"login" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Login the user
	accessToken, refreshToken, err := h.authService.Login(c.Request().Context(), body.Login, body.Password, c.Request().UserAgent())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return tokenResponse(c, accessToken, refreshToken)
}

func (h *Handler) handlePostLogout(c echo.Context) error {
	// Get the refresh token from the cookie
	cookie, err := c.Request().Cookie(RefreshTokenCookieName)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "missing refresh token")
	}
	refreshToken := cookie.Value

	// Logout the user
	if err := h.authService.Logout(c.Request().Context(), refreshToken); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) handlePostLogoutAll(c echo.Context) error {
	// Get the user from the context
	user := c.Get("user").(*model.User)

	// Logout the user from all devices
	if err := h.authService.LogoutAll(c.Request().Context(), user.ID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) handlePostRefresh(c echo.Context) error {
	// Get the refresh token from the cookie
	cookie, err := c.Request().Cookie(RefreshTokenCookieName)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "missing refresh token")
	}
	refreshToken := cookie.Value

	// Refresh the tokens
	accessToken, newRefreshToken, err := h.authService.Refresh(c.Request().Context(), refreshToken, c.Request().UserAgent())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return tokenResponse(c, accessToken, newRefreshToken)
}

func (h *Handler) handleGetVerify(c echo.Context) error {
	// Get the token from the query string
	token := c.QueryParam("token")
	if token == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing token")
	}

	// Verify the token
	err := h.authService.Verify(c.Request().Context(), token)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.String(http.StatusOK, "Verified")
}

func (h *Handler) handlePostForgot(c echo.Context) error {
	var body struct {
		Email string `json:"email" validate:"required,email"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	resetUrl := fmt.Sprintf("%s://%s%s/reset?token=", c.Scheme(), c.Request().Host, strings.TrimSuffix(c.Request().URL.Path, "/forgot"))
	if err := h.authService.Forgot(c.Request().Context(), body.Email, resetUrl); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) handlePostReset(c echo.Context) error {
	// Get the token and password from the request body
	var body struct {
		Token    string `json:"token" validate:"required"`
		Password string `json:"password" validate:"required,min=8"`
	}
	if err := c.Bind(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := c.Validate(&body); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Reset the password
	if err := h.authService.Reset(c.Request().Context(), body.Token, body.Password); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.NoContent(http.StatusOK)
}

func (h *Handler) handleGetProvider(c echo.Context) error {
	gothic.BeginAuthHandler(c.Response(), c.Request().WithContext(context.WithValue(c.Request().Context(), "provider", c.Param("provider"))))
	return nil
}

func (h *Handler) handleGetProviderCallback(c echo.Context) error {
	user, err := gothic.CompleteUserAuth(c.Response(), c.Request().WithContext(context.WithValue(c.Request().Context(), "provider", c.Param("provider"))))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	accessToken, refreshToken, err := h.authService.LoginOAuth(c.Request().Context(), user, c.Request().UserAgent())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return tokenResponse(c, accessToken, refreshToken)
}

func (h *Handler) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Get the access token from the Authorization header
		token := c.Request().Header.Get(AuthorizationHeaderKey)
		if !strings.HasPrefix(token, "Bearer ") {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing or invalid token")
		}
		token = strings.TrimPrefix(token, "Bearer ")

		// Verify the token
		user, err := h.authService.Authenticate(c.Request().Context(), token)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		}

		// Set the user in the context
		c.Set("user", user)

		return next(c)
	}
}

func tokenResponse(c echo.Context, accessToken string, refreshToken string) error {
	// Set the tokens in the response
	c.Response().Header().Set(AuthorizationHeaderKey, "Bearer "+accessToken)

	c.SetCookie(&http.Cookie{
		Name:     RefreshTokenCookieName,
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // true in production
		SameSite: http.SameSiteStrictMode,
	})

	return c.JSON(http.StatusOK, echo.Map{
		"message":       "Login successful",
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
