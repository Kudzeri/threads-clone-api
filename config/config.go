package config

import "os"

type Config struct {
	DBUrl             string
	JWTSecret         string
	OAuthGoogleConfig *OAuthConfig
	OAuthVKConfig     *OAuthConfig
	TelegramConfig    *TelegramConfig
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type TelegramConfig struct {
	BotToken string
}

func LoadConfig() *Config {
	return &Config{
		DBUrl:     os.Getenv("DATABASE_URL"),
		JWTSecret: os.Getenv("JWT_SECRET"),
		OAuthGoogleConfig: &OAuthConfig{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		},
		OAuthVKConfig: &OAuthConfig{
			ClientID:     os.Getenv("VK_CLIENT_ID"),
			ClientSecret: os.Getenv("VK_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("VK_REDIRECT_URL"),
		},
		TelegramConfig: &TelegramConfig{
			BotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
		},
	}
}
