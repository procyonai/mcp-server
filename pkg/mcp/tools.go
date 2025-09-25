package mcp

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/example/mcp-gw/pkg/oauth"
)

// Tool argument and output types
type EchoArgs struct {
	Message string `json:"message" jsonschema:"description:The message to echo back"`
}

type EchoOutput struct {
	EchoedMessage string `json:"echoed_message"`
}

type SumArgs struct {
	A float64 `json:"a" jsonschema:"description:First number"`
	B float64 `json:"b" jsonschema:"description:Second number"`
}

type SumOutput struct {
	Result float64 `json:"result"`
}

type StockArgs struct {
	Symbol string `json:"symbol" jsonschema:"description:Stock symbol (e.g., AAPL, GOOGL)"`
}

type StockOutput struct {
	Symbol      string  `json:"symbol"`
	Price       float64 `json:"price"`
	Currency    string  `json:"currency"`
	LastUpdated string  `json:"last_updated"`
}

// Tool handlers
func HandleEcho(ctx context.Context, request *mcp.CallToolRequest, args EchoArgs) (*mcp.CallToolResult, EchoOutput, error) {
	// Log user details if available
	if accessToken := ctx.Value("access_token"); accessToken != nil {
		if token, ok := accessToken.(*oauth.AccessToken); ok {
			log.Printf("Echo tool called - UserID: %s, ClientID: %s", token.UserID, token.ClientID)
		}
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: "Echo: " + args.Message,
			},
		},
	}, EchoOutput{
		EchoedMessage: args.Message,
	}, nil
}

func HandleSum(ctx context.Context, request *mcp.CallToolRequest, args SumArgs) (*mcp.CallToolResult, SumOutput, error) {
	// Log user details if available
	if accessToken := ctx.Value("access_token"); accessToken != nil {
		if token, ok := accessToken.(*oauth.AccessToken); ok {
			log.Printf("Sum tool called - UserID: %s, ClientID: %s", token.UserID, token.ClientID)
		}
	}

	result := args.A + args.B
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf("The sum of %.2f and %.2f is %.2f", args.A, args.B, result),
			},
		},
	}, SumOutput{
		Result: result,
	}, nil
}

func HandleStockPrice(ctx context.Context, request *mcp.CallToolRequest, args StockArgs) (*mcp.CallToolResult, StockOutput, error) {
	// Log user details if available
	if accessToken := ctx.Value("access_token"); accessToken != nil {
		if token, ok := accessToken.(*oauth.AccessToken); ok {
			log.Printf("Stock price tool called - UserID: %s, ClientID: %s, Symbol: %s", token.UserID, token.ClientID, args.Symbol)
		}
	}

	// Mock stock data with some realistic prices (for demo purposes)
	stockData := map[string]float64{
		"AAPL":  185.25 + rand.Float64()*10 - 5, // Apple
		"GOOGL": 135.50 + rand.Float64()*10 - 5, // Google
		"MSFT":  378.90 + rand.Float64()*10 - 5, // Microsoft
		"AMZN":  145.75 + rand.Float64()*10 - 5, // Amazon
		"TSLA":  205.30 + rand.Float64()*20 - 10, // Tesla (more volatile)
		"NVDA":  485.60 + rand.Float64()*20 - 10, // NVIDIA
		"META":  325.40 + rand.Float64()*15 - 7,  // Meta
		"NFLX":  425.80 + rand.Float64()*15 - 7,  // Netflix
		"AMD":   142.35 + rand.Float64()*10 - 5,  // AMD
		"INTC":  23.45 + rand.Float64()*5 - 2,    // Intel
	}

	symbol := strings.ToUpper(args.Symbol)
	price, exists := stockData[symbol]
	
	if !exists {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: fmt.Sprintf("Stock symbol '%s' not found in demo data. Available symbols: AAPL, GOOGL, MSFT, AMZN, TSLA, NVDA, META, NFLX, AMD, INTC", args.Symbol),
				},
			},
		}, StockOutput{}, fmt.Errorf("symbol not found")
	}

	// Add some randomness to simulate real-time changes
	rand.Seed(time.Now().UnixNano())
	
	output := StockOutput{
		Symbol:      symbol,
		Price:       price,
		Currency:    "USD",
		LastUpdated: time.Now().Format("2006-01-02 15:04:05"),
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf("📈 Stock: %s\n💰 Price: $%.2f USD\n⏰ Last Updated: %s\n\n⚠️ Note: This is demo data for testing purposes", output.Symbol, output.Price, output.LastUpdated),
			},
		},
	}, output, nil
}