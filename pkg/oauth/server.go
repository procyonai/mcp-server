package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
}

type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name,omitempty"`
	CreatedAt    time.Time
}

type AuthCode struct {
	Code         string
	ClientID     string
	RedirectURI  string
	Scope        string
	ExpiresAt    time.Time
	CodeChallenge string
	CodeChallengeMethod string
	OIDCAccessToken string
}

type AccessToken struct {
	Token      string
	ClientID   string
	Scope      string
	UserID     string
	UserEmail  string
	ExpiresAt  time.Time
	CreatedAt  time.Time
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
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
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

	return &Server{
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
	}
}

// HandleMetadata returns OAuth2 authorization server metadata
func (s *Server) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := AuthServerMetadata{
		Issuer:                s.serverURL,
		AuthorizationEndpoint: fmt.Sprintf("%s/authorize", s.serverURL),
		TokenEndpoint:         fmt.Sprintf("%s/token", s.serverURL),
		RegistrationEndpoint:  fmt.Sprintf("%s/register", s.serverURL),
		ScopesSupported:       []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:   []string{"authorization_code"},
		TokenEndpointAuthMethods: []string{"client_secret_post", "none"},
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

	// Build external OIDC authorization URL
	// Use base64 encoding for state to avoid URL encoding issues
	stateData := fmt.Sprintf("%s|%s|%s|%s|%s", clientID, redirectURI, state, codeChallenge, codeChallengeMethod)
	encodedState := base64.URLEncoding.EncodeToString([]byte(stateData))
	
	params := url.Values{}
	params.Add("client_id", s.oidcClientID)
	params.Add("redirect_uri", fmt.Sprintf("%s/callback", s.serverURL))
	params.Add("response_type", "code")
	params.Add("scope", s.oidcScopes)
	params.Add("state", encodedState)

	authURL := fmt.Sprintf("%s?%s", s.oidcAuthURL, params.Encode())
	http.Redirect(w, r, authURL, http.StatusFound)
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

	// Parse the OIDC token response to get the access token
	var oidcTokenResponse TokenResponse
	var oidcAccessToken string = ""
	if err := json.Unmarshal(bodyBytes, &oidcTokenResponse); err != nil {
		log.Printf("⚠️  Could not parse OIDC token response: %v", err)
	} else {
		oidcAccessToken = oidcTokenResponse.AccessToken
		log.Printf("✅ Successfully got OIDC access token: %s", oidcAccessToken[:8]+"...")
	}

	// Generate our own authorization code for the MCP client
	authCode := generateRandomString(32)
	s.authCodes[authCode] = &AuthCode{
		Code:         authCode,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scope:        "openid profile email",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		CodeChallenge: codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		OIDCAccessToken: oidcAccessToken,
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
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

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
	s.tokens[accessToken] = &AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		Scope:     authCode.Scope,
		UserID:    "authenticated_user",
		UserEmail: "",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
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

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       authCode.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
			token.UserID = userInfo.Email // Use email as primary identifier
		}
		
		log.Printf("✅ Updated with REAL user info - UserID: %s, Email: %s, Name: %s", token.UserID, token.UserEmail, userInfo.Name)
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