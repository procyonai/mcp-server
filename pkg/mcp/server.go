package mcp

import (
	"log"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/example/mcp-gw/pkg/oauth"
)

// SetupServer creates and configures the MCP server with all tools
func SetupServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "MCP Generic Server with OAuth",
		Version: "1.0.0",
	}, nil)

	// Add tools
	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Echo back any input provided to it",
	}, HandleEcho)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "sum",
		Description: "Add two numbers together",
	}, HandleSum)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "stock_price",
		Description: "Get current stock price (demo data)",
	}, HandleStockPrice)

	return server
}

// CreateSSEHandler creates the Server-Sent Events handler for MCP
func CreateSSEHandler(server *mcp.Server) http.Handler {
	return mcp.NewSSEHandler(func(request *http.Request) *mcp.Server {
		// Add OAuth token context if available
		if accessToken := request.Context().Value("access_token"); accessToken != nil {
			if token, ok := accessToken.(*oauth.AccessToken); ok {
				log.Printf("MCP request from client: %s, user: %s", token.ClientID, token.UserID)
			}
		}
		
		return server
	}, nil)
}