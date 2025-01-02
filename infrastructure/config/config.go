package config

import (
	"github.com/spf13/viper"
	"strconv"
)

type Config struct {
	Server   ServerConfig
	Keycloak KeycloakConfig
	Auth     AuthConfig
}

type ServerConfig struct {
	Port string
}

type KeycloakConfig struct {
	BaseURL string
	Realm   string
	// Admin client config
	AdminClientID string
	AdminUsername string
	AdminPassword string
	// User operations client config
	ClientID     string
	ClientSecret string
}

type AuthConfig struct {
	AccessTokenCookie        string
	RefreshTokenCookie       string
	AccessTokenDuration      int
	RefreshTokenDuration     int
	CookiePathRoot           string
	CookiePathAuth           string
	CookieDomain             string
	HttpOnlyAccesTokenFlag   bool
	SecureAccesTokenFlag     bool
	HttpOnlyRefreshTokenFlag bool
	SecureRefreshTokenFlag   bool
}

func LoadConfig() (*Config, error) {
	viper.AutomaticEnv()

	accessTokenDuration, _ := strconv.Atoi(viper.GetString("ACCESS_TOKEN_DURATION"))
	refreshTokenDuration, _ := strconv.Atoi(viper.GetString("REFRESH_TOKEN_DURATION"))
	httpOnlyAccessTokenFlag, _ := strconv.ParseBool(viper.GetString("HTTP_ONLY_ACCESS_TOKEN_FLAG"))
	secureAccessTokenFlag, _ := strconv.ParseBool(viper.GetString("SECURE_ACCESS_TOKEN_FLAG"))
	httpOnlyRefreshTokenFlag, _ := strconv.ParseBool(viper.GetString("HTTP_ONLY_REFRESH_TOKEN_FLAG"))
	secureRefreshTokenFlag, _ := strconv.ParseBool(viper.GetString("SECURE_REFRESH_TOKEN_FLAG"))

	// Set up direct mappings for env variables
	viper.AutomaticEnv()

	config := &Config{
		Server: ServerConfig{
			Port: viper.GetString("SERVER_PORT"),
		},
		Keycloak: KeycloakConfig{
			BaseURL:       viper.GetString("KEYCLOAK_BASE_URL"),
			Realm:         viper.GetString("KEYCLOAK_REALM"),
			AdminClientID: viper.GetString("KEYCLOAK_ADMIN_CLIENT_ID"),
			AdminUsername: viper.GetString("KEYCLOAK_ADMIN_USERNAME"),
			AdminPassword: viper.GetString("KEYCLOAK_ADMIN_PASSWORD"),
			ClientID:      viper.GetString("KEYCLOAK_CLIENT_ID"),
			ClientSecret:  viper.GetString("KEYCLOAK_CLIENT_SECRET"),
		},
		Auth: AuthConfig{
			AccessTokenCookie:        viper.GetString("ACCESS_TOKEN_COOKIE_NAME"),
			RefreshTokenCookie:       viper.GetString("REFRESH_TOKEN_COOKIE_NAME"),
			AccessTokenDuration:      accessTokenDuration,
			RefreshTokenDuration:     refreshTokenDuration,
			CookiePathRoot:           viper.GetString("ACCESS_TOKEN_COOKIE_PATH"),
			CookiePathAuth:           viper.GetString("REFRESH_TOKEN_COOKIE_PATH"),
			CookieDomain:             viper.GetString("ACCESS_TOKEN_COOKIE_DOMAIN"),
			HttpOnlyAccesTokenFlag:   httpOnlyAccessTokenFlag,
			SecureAccesTokenFlag:     secureAccessTokenFlag,
			HttpOnlyRefreshTokenFlag: httpOnlyRefreshTokenFlag,
			SecureRefreshTokenFlag:   secureRefreshTokenFlag,
		},
	}

	return config, nil
}
