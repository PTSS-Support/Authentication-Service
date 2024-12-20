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
	BaseURL string `yaml:"baseURL"`
	Realm   string `yaml:"realm"`
	// Admin client config
	AdminClientID string `yaml:"adminClientID"`
	AdminUsername string `yaml:"adminUsername"`
	AdminPassword string `yaml:"adminPassword"`
	// User operations client config
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	viper.AutomaticEnv()

	// TODO: place in .env file
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
