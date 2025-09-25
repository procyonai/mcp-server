# Supported OIDC Providers

This document provides detailed configuration instructions for popular OIDC providers.

## 🎯 Quick Setup

Use the interactive configuration script:
```bash
./configure.sh <provider>
```

Or copy an example configuration:
```bash
cp examples/<provider>.env .env
```

## 📋 Provider-Specific Instructions

### PingOne Identity Cloud

**Configuration:**
```bash
./configure.sh pingone
```

**Manual Setup:**
1. Log into your PingOne admin console
2. Go to Applications → Add Application
3. Choose "OIDC Web App"
4. Set Redirect URI: `http://localhost:8080/callback`
5. Note the Client ID, Client Secret, and Environment ID

**Example .env:**
```bash
OIDC_CLIENT_ID=your-pingone-client-id
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://auth.pingone.com/{environment-id}/as/authorize
OIDC_TOKEN_URL=https://auth.pingone.com/{environment-id}/as/token
```

---

### Okta

**Configuration:**
```bash
./configure.sh okta --domain mycompany.okta.com
```

**Manual Setup:**
1. Log into Okta Admin Dashboard
2. Applications → Create App Integration
3. Choose "OIDC - OpenID Connect" → "Web Application"  
4. Set Redirect URI: `http://localhost:8080/callback`
5. Copy Client ID and Client Secret

**Example .env:**
```bash
OIDC_CLIENT_ID=your-okta-client-id
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://mycompany.okta.com/oauth2/default/v1/authorize
OIDC_TOKEN_URL=https://mycompany.okta.com/oauth2/default/v1/token
```

---

### Google Cloud Identity

**Configuration:**
```bash
./configure.sh google
```

**Manual Setup:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create/select a project
3. Enable Google+ API or IAM API
4. Credentials → Create Credentials → OAuth 2.0 Client IDs
5. Choose "Web application"
6. Add redirect URI: `http://localhost:8080/callback`

**Example .env:**
```bash
OIDC_CLIENT_ID=123456789.apps.googleusercontent.com
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://accounts.google.com/o/oauth2/v2/auth
OIDC_TOKEN_URL=https://oauth2.googleapis.com/token
```

---

### Microsoft Azure AD

**Configuration:**
```bash
./configure.sh azure --tenant-id your-tenant-id
```

**Manual Setup:**
1. Go to [Azure Portal](https://portal.azure.com/)
2. Azure Active Directory → App registrations
3. New registration → Web app
4. Set redirect URI: `http://localhost:8080/callback`
5. Certificates & secrets → New client secret
6. Note Application ID, Client Secret, and Tenant ID

**Example .env:**
```bash
OIDC_CLIENT_ID=your-app-id
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
OIDC_TOKEN_URL=https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
```

---

### Auth0

**Configuration:**
```bash
./configure.sh auth0
```

**Manual Setup:**
1. Log into Auth0 Dashboard
2. Applications → Create Application
3. Choose "Regular Web Applications"
4. Set Allowed Callback URLs: `http://localhost:8080/callback`
5. Copy Client ID and Client Secret

**Example .env:**
```bash
OIDC_CLIENT_ID=your-auth0-client-id
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://mycompany.auth0.com/authorize
OIDC_TOKEN_URL=https://mycompany.auth0.com/oauth/token
```

---

### Keycloak

**Configuration:**
```bash
./configure.sh keycloak
```

**Manual Setup:**
1. Log into Keycloak Admin Console
2. Clients → Create
3. Client Protocol: openid-connect
4. Access Type: confidential
5. Valid Redirect URIs: `http://localhost:8080/callback`
6. Copy Client ID and Client Secret

**Example .env:**
```bash
OIDC_CLIENT_ID=mcp-client
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/auth
OIDC_TOKEN_URL=https://keycloak.example.com/auth/realms/master/protocol/openid-connect/token
```

---

### Custom OIDC Provider

**Configuration:**
```bash
./configure.sh custom
```

For any other OIDC-compliant provider, you need:
- Authorization endpoint URL
- Token endpoint URL  
- Client ID and Client Secret
- Supported scopes (usually `openid profile email`)

**Example .env:**
```bash
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-secret
OIDC_AUTH_URL=https://provider.com/oauth2/authorize
OIDC_TOKEN_URL=https://provider.com/oauth2/token
OIDC_USER_URL=https://provider.com/oauth2/userinfo
OIDC_SCOPES=openid profile email
```

## 🔧 Common Configuration

All providers support these common environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `SERVER_URL` | `http://localhost:8080` | Base server URL |
| `OIDC_SCOPES` | `openid profile email` | OAuth scopes |

## 🚀 Testing Your Configuration

After configuration:

1. **Start the server:**
   ```bash
   ./mcp-server
   ```

2. **Test OAuth discovery:**
   ```bash
   curl http://localhost:8080/.well-known/oauth-authorization-server
   ```

3. **Configure Cursor:**
   ```json
   {
     "mcp-oauth-server": {
       "transport": "sse", 
       "url": "http://localhost:8080/sse"
     }
   }
   ```

4. **Verify OAuth flow works in Cursor**

## 🐛 Troubleshooting

**Common Issues:**

1. **"Invalid redirect URI"**
   - Ensure redirect URI in provider matches: `http://localhost:8080/callback`

2. **"Client not found"**
   - Check OIDC_CLIENT_ID matches your provider configuration

3. **"Invalid client secret"** 
   - Verify OIDC_CLIENT_SECRET is correct and hasn't expired

4. **"Scope not supported"**
   - Adjust OIDC_SCOPES to match provider's supported scopes

5. **"Token endpoint not found"**
   - Verify OIDC_TOKEN_URL is correct for your provider

**Debug Tips:**
- Check server logs for detailed OAuth flow information
- Use browser developer tools to inspect redirect flows
- Verify all URLs use HTTPS in production (HTTP OK for localhost)