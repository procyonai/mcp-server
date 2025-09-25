# Generic MCP OAuth Server

A universal **Model Context Protocol (MCP) server** with **OAuth 2.1** authentication that works with **any OIDC provider** (PingOne, Okta, Google, Azure AD, Auth0, Keycloak, and more).

## 🌟 Features

- ✅ **Universal OIDC Support** - Works with any OAuth 2.1/OIDC provider
- ✅ **Complete OAuth 2.1 Implementation** - Authorization Server with PKCE support
- ✅ **MCP Tools** - Includes echo, sum, and stock_price tools (easily extensible)
- ✅ **Beautiful Approval Dialog** - User-friendly consent flow
- ✅ **Production Ready** - Comprehensive logging, error handling, and security
- ✅ **Easy Configuration** - Environment-based configuration with helper scripts

## 🚀 Quick Start

### 1. Clone and Build
```bash
git clone <repository>
cd mcp-oauth-server
go build -o mcp-server .
```

### 2. Configure Your OIDC Provider

**Option A: Use the Configuration Script (Recommended)**
```bash
# Interactive configuration for popular providers
./configure.sh pingone
./configure.sh okta --domain mycompany.okta.com
./configure.sh google
./configure.sh azure --tenant-id your-tenant-id
./configure.sh custom
```

**Option B: Manual Environment Configuration**
```bash
cp .env.example .env
# Edit .env with your OIDC provider settings
```

### 3. Start the Server
```bash
./mcp-server
```

### 4. Configure Your MCP Client
In Cursor (or other MCP client):
```json
{
  "mcp-oauth-server": {
    "transport": "sse",
    "url": "http://localhost:8080/sse"
  }
}
```

## 🔧 Supported OIDC Providers

### PingOne Identity Cloud
```bash
./configure.sh pingone
```

### Okta
```bash
./configure.sh okta --domain mycompany.okta.com
```

### Google Cloud Identity
```bash
./configure.sh google
```

### Microsoft Azure AD
```bash
./configure.sh azure --tenant-id your-tenant-id
```

### Auth0
```bash
./configure.sh auth0
```

### Keycloak
```bash
./configure.sh keycloak
```

### Custom OIDC Provider
```bash
./configure.sh custom
```

## ⚙️ Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `SERVER_URL` | Server base URL | `http://localhost:8080` |
| `OIDC_CLIENT_ID` | OAuth client ID | `your-client-id` |
| `OIDC_CLIENT_SECRET` | OAuth client secret | `your-client-secret` |
| `OIDC_AUTH_URL` | Authorization endpoint | `https://provider/auth` |
| `OIDC_TOKEN_URL` | Token endpoint | `https://provider/token` |
| `OIDC_USER_URL` | User info endpoint (optional) | `https://provider/userinfo` |
| `OIDC_SCOPES` | OAuth scopes | `openid profile email` |

## 🔒 OAuth 2.1 Flow

1. **Discovery**: MCP client discovers OAuth metadata at `/.well-known/oauth-authorization-server`
2. **Registration**: Client registers dynamically at `/register`  
3. **Authorization**: User visits `/authorize` and approves access
4. **Authentication**: User authenticates with your OIDC provider
5. **Token Exchange**: Client exchanges code for access token at `/token`
6. **Protected Access**: Client accesses MCP tools at `/sse` with Bearer token

## 🛠️ Available MCP Tools

### echo
Echoes back any input message
```json
{"message": "Hello World"}
```

### sum  
Adds two numbers together
```json
{"a": 5, "b": 3}
```

### stock_price
Returns mock stock price data
```json
{"symbol": "AAPL"}
```

## 🔍 Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/oauth-authorization-server` | OAuth metadata discovery |
| `/register` | Dynamic client registration |
| `/authorize` | Authorization + approval dialog |
| `/token` | Token exchange |
| `/callback` | OAuth callback from OIDC provider |
| `/sse` | Protected MCP Server-Sent Events |

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │    │  OAuth Server    │    │  OIDC Provider  │
│   (Cursor)      │    │  (This App)      │    │ (Ping/Okta/etc) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Discover OAuth     │                       │
         │────────────────────► │                       │
         │                       │                       │
         │ 2. Register Client    │                       │  
         │────────────────────► │                       │
         │                       │                       │
         │ 3. Start OAuth Flow   │                       │
         │────────────────────► │                       │
         │                       │                       │
         │ 4. User Approval      │ 5. Redirect to OIDC   │
         │   (Browser Dialog)    │───────────────────────►│
         │                       │                       │
         │                       │ 6. Auth Callback      │
         │                       │◄───────────────────────│
         │                       │                       │
         │ 7. Exchange Token     │                       │
         │────────────────────► │                       │
         │                       │                       │
         │ 8. Access MCP Tools   │                       │
         │────────────────────► │                       │
```

## 🚦 Testing the OAuth Flow

1. **Start the server**:
   ```bash
   ./mcp-server
   ```

2. **Visit the authorization URL** (replace client_id with actual ID from logs):
   ```
   http://localhost:8080/authorize?client_id=<CLIENT_ID>&response_type=code&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=mcp:read
   ```

3. **Approve the request** in the dialog

4. **Complete authentication** with your OIDC provider

5. **Get authorization code** and exchange for token

## 📝 Adding Custom MCP Tools

To add your own MCP tools, edit `main.go`:

```go
// Add tool definition
mcp.AddTool(server, &mcp.Tool{
    Name:        "my_tool",
    Description: "My custom tool",
}, handleMyTool)

// Add handler function  
func handleMyTool(ctx context.Context, request *mcp.CallToolRequest, args MyToolArgs) (*mcp.CallToolResult, MyToolOutput, error) {
    // Your tool logic here
    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: "Tool result"},
        },
    }, MyToolOutput{}, nil
}
```

## 🔐 Security Features

- **OAuth 2.1 Compliance** - Latest OAuth security standards
- **PKCE Support** - Proof Key for Code Exchange for enhanced security  
- **Bearer Token Authentication** - Secure API access
- **CORS Support** - Proper cross-origin handling
- **Request Logging** - Comprehensive audit trail
- **Token Expiration** - Automatic token lifecycle management

### 🚨 Security Best Practices

**Environment Variables:**
- Never commit real credentials to version control
- Use `.env` files for local development (add to `.gitignore`)
- Use secure secret management in production (AWS Secrets Manager, etc.)

**Production Deployment:**
- Use HTTPS only (never HTTP in production)
- Set strong, unique client secrets
- Implement rate limiting
- Monitor OAuth flows for suspicious activity
- Regularly rotate client secrets

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)  
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙋‍♂️ Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Documentation**: Full API documentation available in the code
- **Examples**: Check the `examples/` directory for usage examples

---

**Made with ❤️ for the MCP community**