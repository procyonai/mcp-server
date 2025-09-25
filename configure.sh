#!/bin/bash

# MCP OAuth Server - OIDC Provider Configuration Script
# This script helps you quickly configure different OIDC providers

set -e

echo "🔐 MCP OAuth Server - OIDC Configuration"
echo "========================================"
echo ""

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <provider> [options]"
    echo ""
    echo "Supported providers:"
    echo "  pingone    - PingOne Identity Cloud"
    echo "  okta       - Okta"
    echo "  google     - Google Cloud Identity"
    echo "  azure      - Microsoft Azure AD"
    echo "  auth0      - Auth0"
    echo "  keycloak   - Keycloak"
    echo "  custom     - Custom OIDC provider"
    echo ""
    echo "Examples:"
    echo "  $0 pingone"
    echo "  $0 okta --domain mycompany.okta.com"
    echo "  $0 google"
    echo "  $0 azure --tenant-id your-tenant-id"
    echo ""
    exit 1
fi

PROVIDER=$1
shift

# Function to prompt for input with default
prompt_input() {
    local prompt="$1"
    local default="$2"
    local value
    
    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " value
        echo "${value:-$default}"
    else
        read -p "$prompt: " value
        echo "$value"
    fi
}

# Function to write environment variables
write_env() {
    cat > .env << EOF
# MCP OAuth Server Configuration
# Generated for provider: $PROVIDER
# Generated at: $(date)

PORT=8080
SERVER_URL=http://localhost:8080

OIDC_CLIENT_ID=$OIDC_CLIENT_ID
OIDC_CLIENT_SECRET=$OIDC_CLIENT_SECRET
OIDC_AUTH_URL=$OIDC_AUTH_URL
OIDC_TOKEN_URL=$OIDC_TOKEN_URL
OIDC_USER_URL=$OIDC_USER_URL
OIDC_SCOPES=$OIDC_SCOPES
EOF
}

case $PROVIDER in
    "pingone")
        echo "🏢 Configuring PingOne Identity Cloud"
        echo ""
        ENVIRONMENT_ID=$(prompt_input "PingOne Environment ID")
        OIDC_CLIENT_ID=$(prompt_input "Client ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL="https://auth.pingone.com/$ENVIRONMENT_ID/as/authorize"
        OIDC_TOKEN_URL="https://auth.pingone.com/$ENVIRONMENT_ID/as/token"
        OIDC_USER_URL="https://auth.pingone.com/$ENVIRONMENT_ID/as/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "okta")
        echo "🏢 Configuring Okta"
        echo ""
        DOMAIN=""
        while [[ $# -gt 0 ]]; do
            case $1 in
                --domain) DOMAIN="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        
        DOMAIN=$(prompt_input "Okta Domain (e.g., mycompany.okta.com)" "$DOMAIN")
        OIDC_CLIENT_ID=$(prompt_input "Client ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL="https://$DOMAIN/oauth2/default/v1/authorize"
        OIDC_TOKEN_URL="https://$DOMAIN/oauth2/default/v1/token"
        OIDC_USER_URL="https://$DOMAIN/oauth2/default/v1/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "google")
        echo "🌐 Configuring Google Cloud Identity"
        echo ""
        OIDC_CLIENT_ID=$(prompt_input "Google Client ID (ends with .apps.googleusercontent.com)")
        OIDC_CLIENT_SECRET=$(prompt_input "Google Client Secret")
        OIDC_AUTH_URL="https://accounts.google.com/o/oauth2/v2/auth"
        OIDC_TOKEN_URL="https://oauth2.googleapis.com/token"
        OIDC_USER_URL="https://openidconnect.googleapis.com/v1/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "azure")
        echo "☁️  Configuring Microsoft Azure AD"
        echo ""
        TENANT_ID=""
        while [[ $# -gt 0 ]]; do
            case $1 in
                --tenant-id) TENANT_ID="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        
        TENANT_ID=$(prompt_input "Azure Tenant ID" "$TENANT_ID")
        OIDC_CLIENT_ID=$(prompt_input "Application (client) ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/authorize"
        OIDC_TOKEN_URL="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"
        OIDC_USER_URL="https://graph.microsoft.com/oidc/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "auth0")
        echo "🔐 Configuring Auth0"
        echo ""
        DOMAIN=$(prompt_input "Auth0 Domain (e.g., mycompany.auth0.com)")
        OIDC_CLIENT_ID=$(prompt_input "Client ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL="https://$DOMAIN/authorize"
        OIDC_TOKEN_URL="https://$DOMAIN/oauth/token"
        OIDC_USER_URL="https://$DOMAIN/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "keycloak")
        echo "🔑 Configuring Keycloak"
        echo ""
        SERVER=$(prompt_input "Keycloak Server URL (e.g., https://keycloak.example.com)")
        REALM=$(prompt_input "Realm Name" "master")
        OIDC_CLIENT_ID=$(prompt_input "Client ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL="$SERVER/auth/realms/$REALM/protocol/openid-connect/auth"
        OIDC_TOKEN_URL="$SERVER/auth/realms/$REALM/protocol/openid-connect/token"
        OIDC_USER_URL="$SERVER/auth/realms/$REALM/protocol/openid-connect/userinfo"
        OIDC_SCOPES="openid profile email"
        ;;
        
    "custom")
        echo "⚙️  Configuring Custom OIDC Provider"
        echo ""
        OIDC_CLIENT_ID=$(prompt_input "Client ID")
        OIDC_CLIENT_SECRET=$(prompt_input "Client Secret")
        OIDC_AUTH_URL=$(prompt_input "Authorization URL")
        OIDC_TOKEN_URL=$(prompt_input "Token URL")
        OIDC_USER_URL=$(prompt_input "User Info URL" "")
        OIDC_SCOPES=$(prompt_input "Scopes" "openid profile email")
        ;;
        
    *)
        echo "❌ Unknown provider: $PROVIDER"
        echo "Run '$0' without arguments to see supported providers."
        exit 1
        ;;
esac

echo ""
echo "📝 Configuration Summary:"
echo "========================"
echo "Provider: $PROVIDER"
echo "Client ID: $OIDC_CLIENT_ID"
echo "Authorization URL: $OIDC_AUTH_URL"
echo "Token URL: $OIDC_TOKEN_URL"
echo "User Info URL: $OIDC_USER_URL"
echo "Scopes: $OIDC_SCOPES"
echo ""

read -p "Save this configuration to .env file? (y/N): " confirm
case $confirm in
    [Yy]*)
        write_env
        echo "✅ Configuration saved to .env"
        echo ""
        echo "🚀 You can now start the server with:"
        echo "   go run ."
        echo "   # or"
        echo "   go build -o mcp-server . && ./mcp-server"
        ;;
    *)
        echo "❌ Configuration not saved."
        ;;
esac

echo ""
echo "🔗 After starting the server, configure your MCP client (like Cursor) with:"
echo "   URL: http://localhost:8080/sse"