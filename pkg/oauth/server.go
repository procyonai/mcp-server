package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Server that mimics the TypeScript implementation for MCP clients like Cursor
type Server struct {
	serverURL      string
	oidcClientID   string
	oidcSecret     string
	oidcAuthURL    string
	oidcTokenURL   string
	oidcUserURL    string
	oidcScopes     string
	clients        map[string]*Client
	authCodes      map[string]*AuthCode
	tokens         map[string]*AccessToken
	authRequests   map[string]*AuthorizationRequest
}

type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name,omitempty"`
	CreatedAt    time.Time
}

type AuthCode struct {
	Code                      string
	ClientID                  string
	RedirectURI               string
	Scope                     string
	ExpiresAt                 time.Time
	CodeChallenge             string
	CodeChallengeMethod       string
	OIDCAccessToken           string
	OIDCRefreshToken          string
	OIDCAccessTokenExpiresIn  int
	OIDCRefreshTokenExpiresIn int
}

type AccessToken struct {
	Token               string
	RefreshToken        string
	ClientID            string
	Scope               string
	UserID              string
	UserEmail           string
	ExpiresAt           time.Time
	RefreshTokenExpires time.Time
	CreatedAt           time.Time
}

type ClientRegistrationRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
}

type ClientRegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
	CreatedAt    int64    `json:"client_id_issued_at"`
}

type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	TokenEndpointAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in,omitempty"`
	Scope                 string `json:"scope"`
}

type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type AuthorizationRequest struct {
	RequestID           string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

// getEnvOr returns environment variable value or default
func getEnvOr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

// NewServer creates a new OAuth2 server instance
func NewServer() *Server {
	port := getEnvOr("PORT", "8080")
	serverURL := getEnvOr("SERVER_URL", fmt.Sprintf("http://localhost:%s", port))

	server := &Server{
		serverURL:    serverURL,
		oidcClientID: getEnvOr("OIDC_CLIENT_ID", "your-oidc-client-id"),
		oidcSecret:   getEnvOr("OIDC_CLIENT_SECRET", "your-oidc-client-secret"),
		oidcAuthURL:  getEnvOr("OIDC_AUTH_URL", "https://your-oidc-provider.com/oauth2/authorize"),
		oidcTokenURL: getEnvOr("OIDC_TOKEN_URL", "https://your-oidc-provider.com/oauth2/token"),
		oidcUserURL:  getEnvOr("OIDC_USER_URL", "https://your-oidc-provider.com/oauth2/userinfo"),
		oidcScopes:   getEnvOr("OIDC_SCOPES", "openid profile email"),
		clients:      make(map[string]*Client),
		authCodes:    make(map[string]*AuthCode),
		tokens:       make(map[string]*AccessToken),
		authRequests: make(map[string]*AuthorizationRequest),
	}

	// Start background cleanup routine
	server.startCleanupRoutine()

	return server
}

// HandleMetadata returns OAuth2 authorization server metadata
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := AuthServerMetadata{
		Issuer:                        s.serverURL,
		AuthorizationEndpoint:         fmt.Sprintf("%s/authorize", s.serverURL),
		TokenEndpoint:                 fmt.Sprintf("%s/token", s.serverURL),
		RegistrationEndpoint:          fmt.Sprintf("%s/register", s.serverURL),
		ScopesSupported:               []string{"openid", "profile", "email"},
		ResponseTypesSupported:        []string{"code"},
		GrantTypesSupported:           []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethods:      []string{"client_secret_post", "none"},
		CodeChallengeMethodsSupported: []string{"S256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// HandleRegister handles dynamic client registration
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	clientID := generateRandomString(32)
	clientSecret := ""

	// Only generate secret for confidential clients (those with redirect URIs)
	if len(req.RedirectURIs) > 0 {
		clientSecret = generateRandomString(48)
	}

	client := &Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
		CreatedAt:    time.Now(),
	}

	s.clients[clientID] = client

	response := ClientRegistrationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		ClientName:   req.ClientName,
		CreatedAt:    time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// HandleAuthorize handles the authorization endpoint
func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")
	scope := r.URL.Query().Get("scope")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType != "code" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	// PKCE validation - required for public clients
	if codeChallenge == "" || codeChallengeMethod != "S256" {
		http.Error(w, "PKCE required with S256 method", http.StatusBadRequest)
		return
	}

	// Look up client information and determine client name
	client, exists := s.clients[clientID]
	var clientName string
	if exists && client.Name != "" {
		clientName = client.Name
	} else {
		// Try to extract a friendly name from the redirect URI or client ID
		clientName = s.inferClientName(clientID, redirectURI)
	}

	// Create authorization request and store it temporarily
	requestID := generateRandomString(32)
	authRequest := &AuthorizationRequest{
		RequestID:           requestID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               scope,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute), // Request expires in 10 minutes
	}
	s.authRequests[requestID] = authRequest

	// Parse scopes for display
	scopes := strings.Split(scope, " ")
	if len(scopes) == 0 || scopes[0] == "" {
		scopes = []string{"Access your MCP resources", "Use MCP tools on your behalf"}
	}

	// Show consent page
	s.showConsentPage(w, clientName, requestID, scopes)
}

// showConsentPage renders the consent page
func (s *Server) showConsentPage(w http.ResponseWriter, clientName, requestID string, scopes []string) {
	tmpl, err := template.New("consent").Parse(consentPageTemplate)
	if err != nil {
		log.Printf("Error parsing consent template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ClientName string
		RequestID  string
		Scopes     []string
	}{
		ClientName: clientName,
		RequestID:  requestID,
		Scopes:     scopes,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing consent template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// HandleConsent handles the consent form submission
func (s *Server) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := r.FormValue("request_id")
	action := r.FormValue("action")

	if requestID == "" || action == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Retrieve the authorization request
	authRequest, exists := s.authRequests[requestID]
	if !exists || authRequest.ExpiresAt.Before(time.Now()) {
		if exists {
			delete(s.authRequests, requestID)
		}
		http.Error(w, "Invalid or expired authorization request", http.StatusBadRequest)
		return
	}

	// Clean up the temporary request
	delete(s.authRequests, requestID)

	if action == "deny" {
		// User denied the request - redirect back with error
		params := url.Values{}
		params.Add("error", "access_denied")
		params.Add("error_description", "The user denied the request")
		if authRequest.State != "" {
			params.Add("state", authRequest.State)
		}
		
		redirectURL := fmt.Sprintf("%s?%s", authRequest.RedirectURI, params.Encode())
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	if action == "approve" {
		// User approved - proceed with OIDC authorization
		// Build external OIDC authorization URL
		stateData := fmt.Sprintf("%s|%s|%s|%s|%s", authRequest.ClientID, authRequest.RedirectURI, 
			authRequest.State, authRequest.CodeChallenge, authRequest.CodeChallengeMethod)
		encodedState := base64.URLEncoding.EncodeToString([]byte(stateData))

		params := url.Values{}
		params.Add("client_id", s.oidcClientID)
		params.Add("redirect_uri", fmt.Sprintf("%s/callback", s.serverURL))
		params.Add("response_type", "code")
		params.Add("scope", s.oidcScopes)
		params.Add("state", encodedState)

		authURL := fmt.Sprintf("%s?%s", s.oidcAuthURL, params.Encode())
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}

	http.Error(w, "Invalid action", http.StatusBadRequest)
}

// inferClientName attempts to determine a friendly client name from available information
func (s *Server) inferClientName(clientID, redirectURI string) string {
	// Check for known MCP clients based on redirect URI patterns
	if strings.Contains(redirectURI, "cursor://") {
		return "Cursor"
	}
	if strings.Contains(redirectURI, "vscode://") || strings.Contains(redirectURI, "vscode-insiders://") {
		return "Visual Studio Code"
	}
	if strings.Contains(redirectURI, "zed://") {
		return "Zed"
	}
	if strings.Contains(redirectURI, "windsurf://") {
		return "Windsurf"
	}
	if strings.Contains(redirectURI, "localhost") || strings.Contains(redirectURI, "127.0.0.1") {
		if strings.Contains(redirectURI, ":3000") {
			return "Development Client (Port 3000)"
		}
		return "Local Development Client"
	}
	if strings.HasPrefix(redirectURI, "http://") || strings.HasPrefix(redirectURI, "https://") {
		// Extract domain from URL
		if parsedURL, err := url.Parse(redirectURI); err == nil && parsedURL.Host != "" {
			return fmt.Sprintf("Web Client (%s)", parsedURL.Host)
		}
	}
	if redirectURI == "urn:ietf:wg:oauth:2.0:oob" {
		return "OAuth Out-of-Band Client"
	}

	// Fallback: use first 8 characters of client ID for identification
	if len(clientID) >= 8 {
		return fmt.Sprintf("MCP Client (%s)", clientID[:8])
	}
	
	return "Unknown Application"
}

// HandleCallback handles the OAuth callback from external OIDC provider
func (s *Server) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	// Parse state to extract original client info
	// Decode base64 encoded state
	decodedState, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, "Invalid state encoding", http.StatusBadRequest)
		return
	}

	stateParts := strings.Split(string(decodedState), "|")
	if len(stateParts) != 5 {
		http.Error(w, fmt.Sprintf("Invalid state format: expected 5 parts, got %d", len(stateParts)), http.StatusBadRequest)
		return
	}

	clientID := stateParts[0]
	redirectURI := stateParts[1]
	originalState := stateParts[2]
	codeChallenge := stateParts[3]
	codeChallengeMethod := stateParts[4]

	// Exchange code with external OIDC provider with automatic fallback
	tokenData := url.Values{}
	tokenData.Set("grant_type", "authorization_code")
	tokenData.Set("code", code)
	tokenData.Set("redirect_uri", fmt.Sprintf("%s/callback", s.serverURL))

	// Try both authentication methods with automatic fallback
	resp, err := s.exchangeTokenWithFallback(tokenData)
	if err != nil {
		log.Printf("Error exchanging token with OIDC provider: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the entire response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading OIDC token response: %v", err)
		http.Error(w, "Failed to read OIDC token response", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		// Log the response body for debugging
		bodyStr := string(bodyBytes)
		log.Printf("Token exchange failed with status %d: %s", resp.StatusCode, bodyStr)
		log.Printf("Request URL: %s", s.oidcTokenURL)
		log.Printf("Request data: %s", tokenData.Encode())
		http.Error(w, fmt.Sprintf("Token exchange failed with status: %d", resp.StatusCode), http.StatusBadRequest)
		return
	}

	// Parse the OIDC token response to get the access token and refresh token
	var oidcTokenResponse TokenResponse
	var oidcAccessToken string = ""
	var oidcRefreshToken string = ""
	var oidcAccessTokenExpiresIn int = 0
	var oidcRefreshTokenExpiresIn int = 0
	
	if err := json.Unmarshal(bodyBytes, &oidcTokenResponse); err != nil {
		log.Printf("⚠️  Could not parse OIDC token response: %v", err)
	} else {
		oidcAccessToken = oidcTokenResponse.AccessToken
		oidcRefreshToken = oidcTokenResponse.RefreshToken
		oidcAccessTokenExpiresIn = oidcTokenResponse.ExpiresIn
		oidcRefreshTokenExpiresIn = oidcTokenResponse.RefreshTokenExpiresIn
		
		log.Printf("✅ Successfully got OIDC access token: %s (expires in %d seconds)", oidcAccessToken[:8]+"...", oidcAccessTokenExpiresIn)
		if oidcRefreshToken != "" {
			log.Printf("✅ Successfully got OIDC refresh token: %s", oidcRefreshToken[:8]+"...")
			if oidcRefreshTokenExpiresIn > 0 {
				log.Printf("✅ OIDC refresh token expires in %d seconds", oidcRefreshTokenExpiresIn)
			}
		} else {
			log.Printf("ℹ️  No OIDC refresh token provided by IdP")
		}
	}

	// Generate our own authorization code for the MCP client
	authCode := generateRandomString(32)
	s.authCodes[authCode] = &AuthCode{
		Code:                      authCode,
		ClientID:                  clientID,
		RedirectURI:               redirectURI,
		Scope:                     "openid profile email",
		ExpiresAt:                 time.Now().Add(10 * time.Minute),
		CodeChallenge:             codeChallenge,
		CodeChallengeMethod:       codeChallengeMethod,
		OIDCAccessToken:           oidcAccessToken,
		OIDCRefreshToken:          oidcRefreshToken,
		OIDCAccessTokenExpiresIn:  oidcAccessTokenExpiresIn,
		OIDCRefreshTokenExpiresIn: oidcRefreshTokenExpiresIn,
	}

	// Redirect back to MCP client
	params := url.Values{}
	params.Add("code", authCode)
	if originalState != "" {
		params.Add("state", originalState)
	}

	finalRedirect := fmt.Sprintf("%s?%s", redirectURI, params.Encode())
	http.Redirect(w, r, finalRedirect, http.StatusFound)
}

// HandleToken handles the token endpoint
func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	refreshToken := r.FormValue("refresh_token")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	if grantType == "refresh_token" {
		s.handleRefreshTokenGrant(w, refreshToken, clientID)
		return
	}

	if grantType != "authorization_code" {
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Find and validate authorization code
	authCode, exists := s.authCodes[code]
	if !exists || authCode.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	// Validate client and redirect URI
	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		http.Error(w, "Invalid client or redirect URI", http.StatusBadRequest)
		return
	}

	// Validate PKCE
	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			http.Error(w, "Code verifier required", http.StatusBadRequest)
			return
		}

		// Verify code challenge
		hash := sha256.Sum256([]byte(codeVerifier))
		computedChallenge := base64.URLEncoding.EncodeToString(hash[:])
		computedChallenge = strings.TrimRight(computedChallenge, "=")

		if computedChallenge != authCode.CodeChallenge {
			http.Error(w, "Invalid code verifier", http.StatusBadRequest)
			return
		}
	}

	// Create access token
	accessToken := generateRandomString(64)
	var refreshTokenStr string
	// Only provide refresh token if OIDC provider gave us one
	if authCode.OIDCRefreshToken != "" {
		refreshTokenStr = generateRandomString(64)
	}
	
	// Use OIDC provider's expiration times, with fallbacks
	now := time.Now()
	var accessTokenExpires time.Time
	var refreshTokenExpires time.Time
	
	// Access token expiration from OIDC provider or default to 1 hour
	if authCode.OIDCAccessTokenExpiresIn > 0 {
		accessTokenExpires = now.Add(time.Duration(authCode.OIDCAccessTokenExpiresIn) * time.Second)
		log.Printf("ℹ️  Using OIDC access token expiration: %d seconds", authCode.OIDCAccessTokenExpiresIn)
	} else {
		accessTokenExpires = now.Add(1 * time.Hour) // Default fallback
		log.Printf("ℹ️  Using default access token expiration: 1 hour")
	}
	
	// Refresh token expiration from OIDC provider or default to 30 days
	if refreshTokenStr != "" {
		if authCode.OIDCRefreshTokenExpiresIn > 0 {
			refreshTokenExpires = now.Add(time.Duration(authCode.OIDCRefreshTokenExpiresIn) * time.Second)
			log.Printf("ℹ️  Using OIDC refresh token expiration: %d seconds", authCode.OIDCRefreshTokenExpiresIn)
		} else {
			refreshTokenExpires = now.Add(30 * 24 * time.Hour) // Default 30 days
			log.Printf("ℹ️  Using default refresh token expiration: 30 days")
		}
	}
	
	s.tokens[accessToken] = &AccessToken{
		Token:               accessToken,
		RefreshToken:        refreshTokenStr,
		ClientID:            clientID,
		Scope:               authCode.Scope,
		UserID:              "authenticated_user",
		UserEmail:           "",
		ExpiresAt:           accessTokenExpires,
		RefreshTokenExpires: refreshTokenExpires,
		CreatedAt:           now,
	}

	// Try to fetch user info in the background (don't block OAuth flow)
	// Use the stored OIDC access token if available
	if authCode.OIDCAccessToken != "" {
		log.Printf("🚀 Starting background user info fetch for token: %s", accessToken[:8]+"...")
		go s.fetchAndUpdateUserInfoFromOIDC(accessToken, authCode.OIDCAccessToken)
	} else {
		log.Printf("⚠️  No OIDC access token available for user info fetch")
	}

	// Clean up authorization code
	delete(s.authCodes, code)

	// Calculate actual expires_in seconds for response
	expiresInSeconds := int(accessTokenExpires.Sub(now).Seconds())
	var refreshExpiresInSeconds int
	if !refreshTokenExpires.IsZero() {
		refreshExpiresInSeconds = int(refreshTokenExpires.Sub(now).Seconds())
	}
	
	response := TokenResponse{
		AccessToken:           accessToken,
		RefreshToken:          refreshTokenStr, // Will be empty string if no OIDC refresh token (omitempty will handle it)
		TokenType:             "Bearer",
		ExpiresIn:             expiresInSeconds,
		RefreshTokenExpiresIn: refreshExpiresInSeconds,
		Scope:                 authCode.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRefreshTokenGrant handles refresh token grant requests
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, refreshToken, clientID string) {
	if refreshToken == "" || clientID == "" {
		http.Error(w, "Missing refresh token or client ID", http.StatusBadRequest)
		return
	}

	// Find the access token that has this refresh token
	var existingToken *AccessToken
	var existingAccessToken string
	for token, accessToken := range s.tokens {
		if accessToken.RefreshToken == refreshToken && accessToken.ClientID == clientID {
			existingToken = accessToken
			existingAccessToken = token
			break
		}
	}

	if existingToken == nil {
		http.Error(w, "Invalid refresh token", http.StatusBadRequest)
		return
	}

	// Check if refresh token is expired
	if existingToken.RefreshTokenExpires.Before(time.Now()) {
		// Clean up expired refresh token
		delete(s.tokens, existingAccessToken)
		http.Error(w, "Refresh token expired", http.StatusBadRequest)
		return
	}

	// Generate new access token
	newAccessToken := generateRandomString(64)
	newRefreshToken := generateRandomString(64)
	
	// Create new token with updated expiration
	// For refresh tokens, we use the same expiration strategy as original token
	// since we don't have OIDC context here, use reasonable defaults
	now := time.Now()
	newAccessExpires := now.Add(1 * time.Hour) // Default access token lifetime
	newRefreshExpires := now.Add(30 * 24 * time.Hour) // Default refresh token lifetime
	
	s.tokens[newAccessToken] = &AccessToken{
		Token:               newAccessToken,
		RefreshToken:        newRefreshToken,
		ClientID:            existingToken.ClientID,
		Scope:               existingToken.Scope,
		UserID:              existingToken.UserID,
		UserEmail:            existingToken.UserEmail,
		ExpiresAt:           newAccessExpires,
		RefreshTokenExpires: newRefreshExpires,
		CreatedAt:           now,
	}

	// Remove old access token
	delete(s.tokens, existingAccessToken)

	// Calculate expires_in for response
	expiresInSeconds := int(newAccessExpires.Sub(now).Seconds())
	refreshExpiresInSeconds := int(newRefreshExpires.Sub(now).Seconds())
	
	response := TokenResponse{
		AccessToken:           newAccessToken,
		RefreshToken:          newRefreshToken,
		TokenType:             "Bearer",
		ExpiresIn:             expiresInSeconds,
		RefreshTokenExpiresIn: refreshExpiresInSeconds,
		Scope:                 existingToken.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	log.Printf("✅ Refreshed token for client %s, old token: %s, new token: %s", 
		clientID, existingAccessToken[:8]+"...", newAccessToken[:8]+"...")
}

// AuthMiddleware validates Bearer tokens for protected resources
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			s.sendAuthChallenge(w)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		accessToken, exists := s.tokens[token]

		if !exists || accessToken.ExpiresAt.Before(time.Now()) {
			if exists {
				delete(s.tokens, token)
			}
			s.sendAuthChallenge(w)
			return
		}

		// Add token info to request context
		ctx := context.WithValue(r.Context(), "access_token", accessToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// exchangeTokenWithFallback tries both client authentication methods
func (s *Server) exchangeTokenWithFallback(tokenData url.Values) (*http.Response, error) {
	client := &http.Client{}

	// Method 1: Try HTTP Basic Auth (client_secret_basic) - preferred method
	log.Printf("Attempting token exchange with HTTP Basic Auth")
	req1, err := http.NewRequest("POST", s.oidcTokenURL, strings.NewReader(tokenData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create basic auth request: %v", err)
	}
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.SetBasicAuth(s.oidcClientID, s.oidcSecret)

	resp1, err := client.Do(req1)
	if err != nil {
		log.Printf("Basic Auth request failed: %v", err)
	} else if resp1.StatusCode == http.StatusOK {
		log.Printf("✅ Token exchange successful with HTTP Basic Auth")
		return resp1, nil
	} else if resp1.StatusCode == 401 {
		// 401 likely means unsupported auth method, try fallback
		log.Printf("⚠️  HTTP Basic Auth returned 401, trying form data fallback")
		resp1.Body.Close()
	} else {
		// Other error, return as-is for proper error handling
		log.Printf("HTTP Basic Auth returned status %d, returning for error handling", resp1.StatusCode)
		return resp1, nil
	}

	// Method 2: Fallback to form data (client_secret_post)
	log.Printf("Attempting token exchange with form data (client_secret_post)")
	tokenDataWithCredentials := url.Values{}
	for k, v := range tokenData {
		tokenDataWithCredentials[k] = v
	}
	tokenDataWithCredentials.Set("client_id", s.oidcClientID)
	tokenDataWithCredentials.Set("client_secret", s.oidcSecret)

	resp2, err := http.PostForm(s.oidcTokenURL, tokenDataWithCredentials)
	if err != nil {
		return nil, fmt.Errorf("both auth methods failed - basic auth: %v, form data: %v",
			fmt.Errorf("status %d", resp1.StatusCode), err)
	}

	if resp2.StatusCode == http.StatusOK {
		log.Printf("✅ Token exchange successful with form data fallback")
	} else {
		log.Printf("❌ Both authentication methods failed - Basic Auth: 401, Form Data: %d", resp2.StatusCode)
	}

	return resp2, nil
}

// sendAuthChallenge sends OAuth challenge response
func (s *Server) sendAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="MCP OAuth Server", authorization_uri="%s/authorize"`, s.serverURL))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"error":             "unauthorized",
		"error_description": "Bearer token required",
		"authorization_uri": fmt.Sprintf("%s/authorize", s.serverURL),
		"token_uri":         fmt.Sprintf("%s/token", s.serverURL),
	}

	json.NewEncoder(w).Encode(response)
}

// fetchAndUpdateUserInfoFromOIDC fetches real user info from OIDC provider in the background
func (s *Server) fetchAndUpdateUserInfoFromOIDC(accessToken, oidcAccessToken string) {
	// This runs in a goroutine, so we don't block the OAuth flow
	log.Printf("🔄 Fetching real user info from OIDC provider for token: %s", accessToken[:8]+"...")

	// Fetch user info using the OIDC access token
	userInfo, err := s.fetchUserInfoFromProvider(oidcAccessToken)
	if err != nil {
		log.Printf("⚠️  Failed to fetch user info from OIDC provider: %v", err)
		return
	}

	// Update our access token with real user info
	if token, exists := s.tokens[accessToken]; exists {
		token.UserID = userInfo.Sub
		if userInfo.Email != "" {
			token.UserEmail = userInfo.Email
		}

		log.Printf("✅ Updated with REAL user info - UserID: %s, Email: %s", token.UserID, token.UserEmail)
	} else {
		log.Printf("⚠️  Token %s no longer exists, skipping user info update", accessToken[:8]+"...")
	}
}

// fetchUserInfoFromProvider fetches user info from the OIDC userinfo endpoint
func (s *Server) fetchUserInfoFromProvider(oidcAccessToken string) (*UserInfo, error) {
	log.Printf("🔍 OIDC userinfo URL configured as: %s", s.oidcUserURL)
	if s.oidcUserURL == "" {
		return nil, fmt.Errorf("OIDC userinfo URL not configured")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", s.oidcUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+oidcAccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %v", err)
	}

	return &userInfo, nil
}

// consentPageTemplate is the HTML template for the consent page
var consentPageTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Authorization Request - MCP OAuth Server</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
		.consent-card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
		.header { text-align: center; margin-bottom: 30px; }
		.header h1 { color: #007bff; margin: 0; font-size: 24px; }
		.header p { color: #6c757d; margin: 5px 0; }
		.app-info { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
		.app-name { font-size: 18px; font-weight: bold; color: #495057; }
		.permissions { margin: 20px 0; }
		.permissions h3 { margin: 0 0 10px 0; color: #495057; }
		.permissions ul { margin: 0; padding-left: 20px; }
		.permissions li { margin: 5px 0; color: #6c757d; }
		.actions { display: flex; gap: 12px; justify-content: center; margin-top: 30px; }
		.btn { padding: 12px 24px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; text-decoration: none; display: inline-block; text-align: center; }
		.btn-approve { background: #28a745; color: white; }
		.btn-deny { background: #6c757d; color: white; }
		.btn:hover { opacity: 0.9; }
		.security-info { font-size: 12px; color: #6c757d; text-align: center; margin-top: 20px; }
		.icon { font-size: 48px; margin-bottom: 10px; }
	</style>
</head>
<body>
	<div class="consent-card">
		<div class="header">
			<div class="icon">🔐</div>
			<h1>Authorization Request</h1>
			<p>MCP OAuth Server</p>
		</div>
		
		<div class="app-info">
			<div class="app-name">{{.ClientName}}</div>
			<p>wants to access your MCP resources</p>
		</div>
		
		<div class="permissions">
			<h3>This application will be able to:</h3>
			<ul>
				{{range .Scopes}}
				<li>{{.}}</li>
				{{end}}
			</ul>
		</div>
		
		<form method="post" action="/consent">
			<input type="hidden" name="request_id" value="{{.RequestID}}">
			<div class="actions">
				<button type="submit" name="action" value="deny" class="btn btn-deny">Deny</button>
				<button type="submit" name="action" value="approve" class="btn btn-approve">Approve</button>
			</div>
		</form>
		
		<div class="security-info">
			You will be redirected to your identity provider for authentication
		</div>
	</div>
</body>
</html>
`

// cleanupExpiredTokens removes expired tokens and auth codes
func (s *Server) cleanupExpiredTokens() {
	now := time.Now()
	
	// Clean up tokens based on refresh token availability
	for token, accessToken := range s.tokens {
		accessExpired := accessToken.ExpiresAt.Before(now)
		
		if accessToken.RefreshToken == "" {
			// No refresh token available - clean up when access token expires
			if accessExpired {
				delete(s.tokens, token)
				log.Printf("🧹 Cleaned up expired access token (no refresh token): %s", token[:8]+"...")
			}
		} else {
			// Has refresh token - only clean up when both access and refresh tokens expire
			refreshExpired := accessToken.RefreshTokenExpires.Before(now)
			
			if accessExpired && refreshExpired {
				// Both access and refresh tokens are expired - safe to delete
				delete(s.tokens, token)
				log.Printf("🧹 Cleaned up fully expired token entry: %s", token[:8]+"...")
			} else if accessExpired && !refreshExpired {
				// Only access token expired, refresh token still valid - keep the entry
				log.Printf("ℹ️  Access token expired but refresh token valid: %s", token[:8]+"...")
			}
		}
	}
	
	// Clean up expired auth codes
	for code, authCode := range s.authCodes {
		if authCode.ExpiresAt.Before(now) {
			delete(s.authCodes, code)
			log.Printf("🧹 Cleaned up expired auth code: %s", code[:8]+"...")
		}
	}
	
	// Clean up expired authorization requests
	for requestID, authRequest := range s.authRequests {
		if authRequest.ExpiresAt.Before(now) {
			delete(s.authRequests, requestID)
			log.Printf("🧹 Cleaned up expired authorization request: %s", requestID[:8]+"...")
		}
	}
}

// startCleanupRoutine starts a background goroutine to clean up expired tokens
func (s *Server) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				s.cleanupExpiredTokens()
			}
		}
	}()
}
