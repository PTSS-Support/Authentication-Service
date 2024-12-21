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
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin"

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
            "serviceAccountsEnabled": true,
            "authorizationServicesEnabled": true,
            "directAccessGrantsEnabled": true,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": false,
            "publicClient": false,
            "redirectUris": ["*"],
            "clientAuthenticatorType": "client-secret",
            "defaultRoles": ["manage-users", "view-users"]
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
    else -l keycloak-init.sh
        echo "APP_KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET" > .env
        echo "Created .env file with client secret"
    fi
else
    echo "Client already exists, skipping creation..."
fi

USER_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/users?username=$ADMIN_USERNAME" | jq '. | length')

if [ "$USER_EXISTS" == "0" ]; then
    echo "Creating admin user..."
    curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d '{
            "username": "'"$ADMIN_USERNAME"'",
            "enabled": true,
            "credentials": [{
                "type": "password",
                "value": "'"$ADMIN_PASSWORD"'",
                "temporary": false
            }],
            "realmRoles": ["admin"]
        }' \
        "http://keycloak:8080/admin/realms/$REALM_NAME/users"
else
    echo "Admin user already exists, skipping creation..."
fi

CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')

SERVICE_ACCOUNT_USER=$(curl -H "Authorization: Bearer $TOKEN" \
    "http://keycloak:8080/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/service-account-user" | jq -r '.id')

REALM_MANAGEMENT_CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" "http://keycloak:8080/admin/realms/$REALM_NAME/clients?clientId=realm-management" | jq -r '.[0].id')

# Assign necessary roles for user management
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d '[
        {"id":"manage-users-role-id", "name":"manage-users"},
        {"id":"view-users-role-id", "name":"view-users"},
        {"id":"query-users-role-id", "name":"query-users"}
    ]' \
    "http://keycloak:8080/admin/realms/$REALM_NAME/users/$SERVICE_ACCOUNT_USER/role-mappings/clients/$REALM_MANAGEMENT_CLIENT_UUID"

echo "Initialization complete!"