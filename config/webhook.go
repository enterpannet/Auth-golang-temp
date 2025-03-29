package config

// DefaultWebhookConfig returns default webhook configuration with safe defaults
func DefaultWebhookConfig() WebhookConfig {
	return WebhookConfig{
		Line: struct {
			Enabled       bool   `mapstructure:"enabled"`
			ChannelID     string `mapstructure:"channel_id"`
			ChannelSecret string `mapstructure:"channel_secret"`
			CallbackURL   string `mapstructure:"callback_url"`
		}{
			Enabled:       false,
			ChannelID:     "",
			ChannelSecret: "",
			CallbackURL:   "/webhooks/line",
		},
		Facebook: struct {
			Enabled     bool   `mapstructure:"enabled"`
			AppID       string `mapstructure:"app_id"`
			AppSecret   string `mapstructure:"app_secret"`
			VerifyToken string `mapstructure:"verify_token"`
			CallbackURL string `mapstructure:"callback_url"`
		}{
			Enabled:     false,
			AppID:       "",
			AppSecret:   "",
			VerifyToken: "auth_service_webhook_verify_token",
			CallbackURL: "/webhooks/facebook",
		},
		Twitter: struct {
			Enabled           bool   `mapstructure:"enabled"`
			ConsumerKey       string `mapstructure:"consumer_key"`
			ConsumerSecret    string `mapstructure:"consumer_secret"`
			AccessToken       string `mapstructure:"access_token"`
			AccessTokenSecret string `mapstructure:"access_token_secret"`
			CallbackURL       string `mapstructure:"callback_url"`
		}{
			Enabled:           false,
			ConsumerKey:       "",
			ConsumerSecret:    "",
			AccessToken:       "",
			AccessTokenSecret: "",
			CallbackURL:       "/webhooks/twitter",
		},
	}
}
