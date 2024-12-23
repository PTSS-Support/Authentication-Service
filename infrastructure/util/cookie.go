package util

import (
	"fmt"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/config"
	"github.com/gin-gonic/gin"
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
	ctx.SetCookie(
		cu.config.Auth.AccessTokenCookie,
		accessToken,
		cu.config.Auth.AccessTokenDuration,
		cu.config.Auth.CookiePathRoot,
		cu.config.Auth.CookieDomain,
		cu.config.Auth.SecureAccesTokenFlag,
		cu.config.Auth.HttpOnlyAccesTokenFlag,
	)

	ctx.SetCookie(
		cu.config.Auth.RefreshTokenCookie,
		refreshToken,
		cu.config.Auth.RefreshTokenDuration,
		cu.config.Auth.CookiePathAuth,
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
