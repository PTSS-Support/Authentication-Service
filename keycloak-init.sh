#!/bin/bash
set -e

# Wait for Keycloak to be ready
until curl -f http://keycloak:8080/health/ready; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

# Login to get admin token
echo "Logging in as admin..."
TOKEN=$(curl -d "client_id=admin-cli" -d "username=admin" -d "password=admin" -d "grant_type=password" "http://keycloak:8080/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

REALM_NAME="PTSS-Support-Realm"
CLIENT_ID="authentication-service"

# Check if realm exists
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME")

if [ "$REALM_EXISTS" == "404" ]; then
    echo "Creating realm..."
    curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '{"realm":"'"$REALM_NAME"'", "enabled":true}' \
        "http://keycloak:8080/admin/realms"
else
    echo "Realm already exists, skipping creation..."
fi

# Check if client exists
CLIENT_EXISTS=$(curl -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq '. | length')

if [ "$CLIENT_EXISTS" == "0" ]; then
    echo "Creating client..."
    curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '{
            "clientId": "'"$CLIENT_ID"'",
            "enabled": true,
            "protocol": "openid-connect",
            "publicClient": false,
            "redirectUris": ["*"],
            "clientAuthenticatorType": "client-secret"
        }' \
        "http://keycloak:8080/admin/realms/$REALM_NAME/clients"

    # Get client secret for the new client
    echo "Getting client secret..."
    CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
    CLIENT_SECRET=$(curl -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" | jq -r '.value')

    # Update .env file only if we created a new client
    if [ -f .env ]; then
        if ! grep -q "APP_KEYCLOAK_CLIENT_SECRET=" .env; then
            echo "APP_KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET" >> .env
            echo "Client secret added to .env file"
        fi
    elsels -l keycloak-init.sh
        echo "\n" >> .env
        echo "APP_KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET" > .env
        echo "Created .env file with client secret"
    fi
else
    echo "Client already exists, skipping creation..."
fi

echo "Initialization complete!"