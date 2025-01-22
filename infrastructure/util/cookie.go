package util

import (
	"fmt"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/gin-gonic/gin"
	"net/http"
)

type CookieUtil struct {
	config *config.Config
}

func NewCookieUtil(config *config.Config) *CookieUtil {
	return &CookieUtil{
		config: config,
	}
}

func (cu *CookieUtil) SetAuthCookies(ctx *gin.Context, accessToken, refreshToken string) {
	cookie := &http.Cookie{
		Name:     cu.config.Auth.AccessTokenCookie,
		Value:    accessToken,
		MaxAge:   cu.config.Auth.AccessTokenDuration,
		Path:     cu.config.Auth.CookiePathRoot,
		Domain:   cu.config.Auth.CookieDomain,
		Secure:   cu.config.Auth.SecureAccesTokenFlag,
		HttpOnly: cu.config.Auth.HttpOnlyAccesTokenFlag,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(ctx.Writer, cookie)

	cookie = &http.Cookie{
		Name:     cu.config.Auth.RefreshTokenCookie,
		Value:    refreshToken,
		MaxAge:   cu.config.Auth.RefreshTokenDuration,
		Path:     cu.config.Auth.CookiePathRoot,
		Domain:   cu.config.Auth.CookieDomain,
		Secure:   cu.config.Auth.SecureRefreshTokenFlag,
		HttpOnly: cu.config.Auth.HttpOnlyRefreshTokenFlag,
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(ctx.Writer, cookie)
}

func (cu *CookieUtil) ClearAuthCookies(ctx *gin.Context) {
	ctx.SetCookie(
		cu.config.Auth.AccessTokenCookie,
		"",
		-1,
		cu.config.Auth.CookiePathRoot,
		cu.config.Auth.CookieDomain,
		cu.config.Auth.SecureAccesTokenFlag,
		cu.config.Auth.HttpOnlyAccesTokenFlag,
	)

	ctx.SetCookie(
		cu.config.Auth.RefreshTokenCookie,
		"",
		-1,
		cu.config.Auth.CookiePathRoot,
		cu.config.Auth.CookieDomain,
		cu.config.Auth.SecureRefreshTokenFlag,
		cu.config.Auth.HttpOnlyRefreshTokenFlag,
	)
}

func (cu *CookieUtil) GetAccessTokenFromCookie(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie(cu.config.Auth.AccessTokenCookie)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMissingToken, err)
	}

	if token == "" {
		return "", errors.ErrMissingToken
	}

	return token, nil
}

func (cu *CookieUtil) GetRefreshTokenFromCookie(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie(cu.config.Auth.RefreshTokenCookie)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMissingToken, err)
	}

	if token == "" {
		return "", errors.ErrMissingToken
	}

	return token, nil
}

func (cu *CookieUtil) GetPINFromCookie(ctx *gin.Context) (string, error) {
	pin, err := ctx.Cookie("pin") // Use the actual cookie name from your config
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMissingPIN, err)
	}

	if pin == "" {
		return "", errors.ErrMissingPIN
	}

	return pin, nil
}
