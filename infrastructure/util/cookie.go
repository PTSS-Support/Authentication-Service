package util

import (
	"fmt"
	"github.com/PTSS-Support/identity-service/domain/errors"
	"github.com/PTSS-Support/identity-service/infrastructure/constants"
	"github.com/gin-gonic/gin"
)

func SetAuthCookies(ctx *gin.Context, accessToken, refreshToken string) {
	ctx.SetCookie(
		constants.AccessTokenCookie,
		accessToken,
		constants.AccessTokenDuration,
		constants.CookiePathRoot,
		"",   // empty domain = current domain
		true, // secure
		true, // httpOnly
	)

	ctx.SetCookie(
		constants.RefreshTokenCookie,
		refreshToken,
		constants.RefreshTokenDuration,
		constants.CookiePathAuth,
		"",
		true,
		true,
	)
}
func GetAccessTokenFromCookie(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie(constants.AccessTokenCookie)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMissingToken, err)
	}

	if token == "" {
		return "", errors.ErrMissingToken
	}

	return token, nil
}

func GetRefreshTokenFromCookie(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie(constants.RefreshTokenCookie)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errors.ErrMissingToken, err)
	}

	if token == "" {
		return "", errors.ErrMissingToken
	}

	return token, nil
}
