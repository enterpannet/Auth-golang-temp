package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/example/auth-service/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthProvider represents the available third-party OAuth providers
type OAuthProvider string

const (
	GoogleOAuthProvider   OAuthProvider = "google"
	FacebookOAuthProvider OAuthProvider = "facebook"
	GithubOAuthProvider   OAuthProvider = "github"
	AppleOAuthProvider    OAuthProvider = "apple"
)

// OAuthManager handles OAuth operations
type OAuthManager struct {
	Config     *config.Config
	HttpClient *http.Client
	Configs    map[OAuthProvider]*oauth2.Config
}

// NewOAuthManager creates a new OAuth manager
func NewOAuthManager(cfg *config.Config) *OAuthManager {
	// Create HTTP client with reasonable timeout
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create OAuth configs for each provider
	configs := make(map[OAuthProvider]*oauth2.Config)

	// Google OAuth config
	if googleCfg, ok := cfg.Auth.OAuthProviders["google"]; ok && googleCfg.ClientID != "" {
		configs[GoogleOAuthProvider] = &oauth2.Config{
			ClientID:     googleCfg.ClientID,
			ClientSecret: googleCfg.ClientSecret,
			RedirectURL:  googleCfg.RedirectURL,
			Scopes:       googleCfg.Scopes,
			Endpoint:     google.Endpoint,
		}
	}

	// Facebook OAuth config
	if fbCfg, ok := cfg.Auth.OAuthProviders["facebook"]; ok && fbCfg.ClientID != "" {
		configs[FacebookOAuthProvider] = &oauth2.Config{
			ClientID:     fbCfg.ClientID,
			ClientSecret: fbCfg.ClientSecret,
			RedirectURL:  fbCfg.RedirectURL,
			Scopes:       fbCfg.Scopes,
			Endpoint:     facebook.Endpoint,
		}
	}

	// GitHub OAuth config
	if githubCfg, ok := cfg.Auth.OAuthProviders["github"]; ok && githubCfg.ClientID != "" {
		configs[GithubOAuthProvider] = &oauth2.Config{
			ClientID:     githubCfg.ClientID,
			ClientSecret: githubCfg.ClientSecret,
			RedirectURL:  githubCfg.RedirectURL,
			Scopes:       githubCfg.Scopes,
			Endpoint:     github.Endpoint,
		}
	}

	return &OAuthManager{
		Config:     cfg,
		HttpClient: httpClient,
		Configs:    configs,
	}
}

// UserInfo contains standardized user information from OAuth providers
type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	ProviderID    string `json:"provider_id"`
	Provider      string `json:"provider"`
}

// GetAuthURL returns the OAuth authorization URL for the specified provider
func (o *OAuthManager) GetAuthURL(provider OAuthProvider, state string) (string, error) {
	config, ok := o.Configs[provider]
	if !ok {
		return "", fmt.Errorf("unsupported OAuth provider: %s", provider)
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce), nil
}

// Exchange exchanges an authorization code for an OAuth token
func (o *OAuthManager) Exchange(ctx context.Context, provider OAuthProvider, code string) (*oauth2.Token, error) {
	config, ok := o.Configs[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}

	return config.Exchange(ctx, code)
}

// GetUserInfo fetches user information from the OAuth provider
func (o *OAuthManager) GetUserInfo(ctx context.Context, provider OAuthProvider, token *oauth2.Token) (*UserInfo, error) {
	config, ok := o.Configs[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}

	// Get an OAuth2 client
	client := config.Client(ctx, token)

	// Get provider-specific user info URL
	var userInfoURL string
	switch provider {
	case GoogleOAuthProvider:
		userInfoURL = o.Config.Auth.OAuthProviders["google"].UserInfoURL
	case FacebookOAuthProvider:
		userInfoURL = o.Config.Auth.OAuthProviders["facebook"].UserInfoURL
	case GithubOAuthProvider:
		userInfoURL = o.Config.Auth.OAuthProviders["github"].UserInfoURL
	default:
		return nil, errors.New("unknown provider")
	}

	// Make the request to get user info
	response, err := client.Get(userInfoURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Check response status
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("OAuth API error: %d - %s", response.StatusCode, string(body))
	}

	// Read the response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	// Parse the provider-specific response to our standardized format
	userInfo := &UserInfo{
		Provider: string(provider),
	}

	// Different providers have different response formats
	switch provider {
	case GoogleOAuthProvider:
		var googleInfo struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			VerifiedEmail bool   `json:"verified_email"`
			Name          string `json:"name"`
			GivenName     string `json:"given_name"`
			FamilyName    string `json:"family_name"`
			Picture       string `json:"picture"`
			Locale        string `json:"locale"`
		}

		if err := json.Unmarshal(body, &googleInfo); err != nil {
			return nil, err
		}

		userInfo.ID = googleInfo.ID
		userInfo.Email = googleInfo.Email
		userInfo.VerifiedEmail = googleInfo.VerifiedEmail
		userInfo.Name = googleInfo.Name
		userInfo.GivenName = googleInfo.GivenName
		userInfo.FamilyName = googleInfo.FamilyName
		userInfo.Picture = googleInfo.Picture
		userInfo.Locale = googleInfo.Locale
		userInfo.ProviderID = googleInfo.ID

	case FacebookOAuthProvider:
		var fbInfo struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Email   string `json:"email"`
			Picture struct {
				Data struct {
					URL string `json:"url"`
				} `json:"data"`
			} `json:"picture"`
		}

		if err := json.Unmarshal(body, &fbInfo); err != nil {
			return nil, err
		}

		userInfo.ID = fbInfo.ID
		userInfo.Email = fbInfo.Email
		userInfo.Name = fbInfo.Name
		userInfo.Picture = fbInfo.Picture.Data.URL
		userInfo.ProviderID = fbInfo.ID
		userInfo.VerifiedEmail = true // Facebook only returns verified emails

	case GithubOAuthProvider:
		var githubInfo struct {
			ID        int    `json:"id"`
			Login     string `json:"login"`
			Name      string `json:"name"`
			AvatarURL string `json:"avatar_url"`
			Email     string `json:"email"`
		}

		if err := json.Unmarshal(body, &githubInfo); err != nil {
			return nil, err
		}

		userInfo.ID = fmt.Sprintf("%d", githubInfo.ID)
		userInfo.Email = githubInfo.Email
		userInfo.Name = githubInfo.Name
		userInfo.Picture = githubInfo.AvatarURL
		userInfo.ProviderID = fmt.Sprintf("%d", githubInfo.ID)
	}

	// Ensure we have at least an ID
	if userInfo.ID == "" {
		return nil, errors.New("could not get user ID from OAuth provider")
	}

	return userInfo, nil
}

// RefreshToken refreshes an OAuth token
func (o *OAuthManager) RefreshToken(ctx context.Context, provider OAuthProvider, refreshToken string) (*oauth2.Token, error) {
	config, ok := o.Configs[provider]
	if !ok {
		return nil, fmt.Errorf("unsupported OAuth provider: %s", provider)
	}

	// Create a token with the refresh token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	// Get a new token source using the refresh token
	tokenSource := config.TokenSource(ctx, token)

	// Get a new token
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

// ValidateState validates the state parameter to prevent CSRF attacks
// In a real implementation, this would check against a stored state in the user's session
func (o *OAuthManager) ValidateState(providedState, expectedState string) bool {
	// Simple equality check - in practice, this would use a secure time constant comparison
	return providedState == expectedState
}
