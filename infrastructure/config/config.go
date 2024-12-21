package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Keycloak KeycloakConfig
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

func LoadConfig() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")

	// Read the env file
	err := viper.ReadInConfig()
	if err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

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
	}

	return config, nil
}
