package util

import (
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
