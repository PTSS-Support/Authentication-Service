package constants

const (
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"

	AccessTokenDuration  = 15 * 60           // 15 minutes in seconds
	RefreshTokenDuration = 30 * 24 * 60 * 60 // 30 days in seconds

	CookiePathAuth = "/auth"
	CookiePathRoot = "/"
)
