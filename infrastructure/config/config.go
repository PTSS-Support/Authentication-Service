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
	BaseURL       string
	Realm         string
	ClientID      string
	ClientSecret  string
	AdminUsername string
	AdminPassword string
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	viper.AutomaticEnv()

	viper.SetDefault("server.port", "8081")
	viper.SetDefault("keycloak.baseURL", "http://localhost:8080")
	viper.SetDefault("keycloak.realm", "master")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
