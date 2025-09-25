package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/example/mcp-gw/pkg/mcp"
	"github.com/example/mcp-gw/pkg/oauth"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: No .env file found or error loading it: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create the MCP server
	mcpServer := mcp.SetupServer()

	// Create OAuth 2.1 Authorization Server for MCP clients like Cursor
	oauthServer := oauth.NewServer()

	// Create SSE handler with OAuth context
	sseHandler := mcp.CreateSSEHandler(mcpServer)

	// Add request logging middleware
	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("\n[SERVER] 🌐 Incoming request: %s %s\n", r.Method, r.URL.String())
			fmt.Printf("[SERVER] 🌐 User-Agent: %s\n", r.Header.Get("User-Agent"))
			fmt.Printf("[SERVER] 🌐 Remote Addr: %s\n", r.RemoteAddr)
			fmt.Printf("[SERVER] 🌐 Content-Type: %s\n", r.Header.Get("Content-Type"))
			next.ServeHTTP(w, r)
		})
	}

	// Setup OAuth 2.1 Authorization Server endpoints (standard OAuth)
	http.Handle("/", loggingMiddleware(http.HandlerFunc(handleHome)))
	http.Handle("/.well-known/oauth-authorization-server", loggingMiddleware(http.HandlerFunc(oauthServer.HandleMetadata)))
	
	// Handle Cursor-specific OAuth discovery paths
	http.Handle("/.well-known/oauth-protected-resource/sse", loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[CURSOR] 🎯 Cursor trying to find OAuth metadata at: %s\n", r.URL.Path)
		// Redirect to the correct metadata endpoint
		http.Redirect(w, r, "/.well-known/oauth-authorization-server", http.StatusFound)
	})))
	
	http.Handle("/.well-known/oauth-authorization-server/sse", loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[CURSOR] 🎯 Cursor trying to find OAuth metadata at: %s\n", r.URL.Path)
		// Redirect to the correct metadata endpoint
		http.Redirect(w, r, "/.well-known/oauth-authorization-server", http.StatusFound)
	})))
	
	http.Handle("/register", loggingMiddleware(http.HandlerFunc(oauthServer.HandleRegister)))
	http.Handle("/authorize", loggingMiddleware(http.HandlerFunc(oauthServer.HandleAuthorize)))
	http.Handle("/token", loggingMiddleware(http.HandlerFunc(oauthServer.HandleToken)))
	http.Handle("/callback", loggingMiddleware(http.HandlerFunc(oauthServer.HandleCallback)))
	
	// Protect the MCP SSE endpoint with OAuth
	http.Handle("/sse", loggingMiddleware(oauthServer.AuthMiddleware(sseHandler)))

	log.Printf("Starting MCP OAuth Server on port %s", port)
	log.Printf("Visit http://localhost:%s for server info", port)
	log.Printf("OAuth 2.1 Authorization Server endpoints:")
	log.Printf("  Authorization Server Metadata: http://localhost:%s/.well-known/oauth-authorization-server", port)
	log.Printf("  Client Registration: http://localhost:%s/register", port)
	log.Printf("  Authorization: http://localhost:%s/authorize", port)
	log.Printf("  Token: http://localhost:%s/token", port)
	log.Printf("  OAuth Callback: http://localhost:%s/callback", port)
	log.Printf("  Protected MCP Resource: http://localhost:%s/sse", port)
	log.Printf("External OIDC Provider: %s", getEnvOr("OIDC_AUTH_URL", "https://your-oidc-provider.com/oauth2/authorize"))
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html>
		<head>
			<title>MCP Server with OAuth 2.1</title>
			<style>
				body { font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
				.card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #007bff; }
				.endpoint { background: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 4px; font-family: monospace; }
				code { background: #e9ecef; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
				pre { background: #e9ecef; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: monospace; }
				.spec-badge { background: #28a745; color: white; padding: 4px 8px; border-radius: 12px; font-size: 12px; }
			</style>
		</head>
		<body>
			<h1>🔐 MCP OAuth Server <span class="spec-badge">OAuth 2.1 + MCP</span></h1>
			
			<div class="card">
				<h2>📊 Available MCP Tools</h2>
				<ul>
					<li><strong>echo</strong> - Echo back any message</li>
					<li><strong>sum</strong> - Add two numbers together</li>
					<li><strong>stock_price</strong> - Get stock prices (demo data)</li>
				</ul>
				<p><em>All tools are protected by OAuth 2.1 tokens. Authentication via external OIDC provider.</em></p>
			</div>

			<div class="card">
				<h2>🔍 OAuth 2.1 Authorization Server Discovery</h2>
				<p>This server acts as an <strong>OAuth 2.1 Authorization Server</strong> for MCP clients like Cursor. It uses external OIDC providers for user authentication:</p>
				<div class="endpoint">GET /.well-known/oauth-authorization-server</div>
				<p>MCP clients will automatically discover OAuth endpoints and perform standard OAuth 2.1 flows with PKCE support.</p>
			</div>

			<div class="card">
				<h2>🚀 MCP Client Integration</h2>
				<p><strong>For MCP clients (like Cursor):</strong></p>
				<ol>
					<li>Configure your MCP client to connect to: <code>http://localhost:8080/sse</code></li>
					<li>The client will automatically discover OAuth endpoints via the metadata endpoint</li>
					<li>Client performs OAuth 2.1 authorization flow with PKCE</li>
					<li>User authenticates via external OIDC provider (redirected automatically)</li>
					<li>Client receives access token and can access MCP tools</li>
				</ol>
				
				<h3>Cursor Configuration:</h3>
				<pre><code>{
  "mcp-oauth-server": {
    "transport": "sse",
    "url": "http://localhost:8080/sse"
  }
}</code></pre>
			</div>

			<div class="card">
				<h2>🔧 OAuth 2.1 Authorization Server Endpoints</h2>
				<h3>Discovery & Registration:</h3>
				<div class="endpoint">GET /.well-known/oauth-authorization-server - Authorization Server Metadata</div>
				<div class="endpoint">POST /register - Dynamic Client Registration</div>
				
				<h3>OAuth Flow:</h3>
				<div class="endpoint">GET /authorize - Authorization Endpoint</div>
				<div class="endpoint">POST /token - Token Endpoint</div>
				<div class="endpoint">GET /callback - OAuth Callback (from OIDC Provider)</div>
				
				<h3>Protected Resource:</h3>
				<div class="endpoint">POST /sse - MCP Server-Sent Events (Bearer token required)</div>
			</div>

			<div class="card">
				<h2>🛡️ Security Features</h2>
				<ul>
					<li>✅ <strong>OAuth 2.1 Authorization Server</strong> - Full OAuth implementation</li>
					<li>✅ <strong>PKCE Support</strong> - Code challenge/verifier validation</li>
					<li>✅ <strong>Dynamic Client Registration</strong> - RFC 7591 compliance</li>
					<li>✅ <strong>Generic OIDC Integration</strong> - Works with any OIDC provider</li>
					<li>✅ <strong>Bearer Token Protection</strong> - All MCP endpoints secured</li>
					<li>✅ <strong>Standard OAuth Discovery</strong> - RFC 8414 metadata endpoint</li>
				</ul>
			</div>

			<div class="card">
				<h2>⚙️ Configuration</h2>
				<h3>OAuth 2.1 Flow:</h3>
				<pre><code>1. MCP Client discovers OAuth endpoints via /.well-known/oauth-authorization-server
2. Client registers (optional) via POST /register  
3. Client redirects user to /authorize
4. Server redirects to external OIDC provider for authentication
5. OIDC provider redirects back to /callback
6. Server issues access token via /token
7. Client accesses /sse with Bearer token</code></pre>
				<p><em>This server acts as a complete OAuth 2.1 Authorization Server, using external OIDC providers for user authentication while managing tokens and client relationships locally.</em></p>
			</div>
		</body>
		</html>
	`)
}

// getEnvOr returns environment variable value or default
func getEnvOr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}