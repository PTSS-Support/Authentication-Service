#!/bin/bash
set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Required environment variables check
required_vars=(
    "KEYCLOAK_URL"
    "KEYCLOAK_ADMIN_CLIENT_ID"
    "KEYCLOAK_ADMIN_USERNAME"
    "KEYCLOAK_ADMIN_PASSWORD"
    "KEYCLOAK_REALM"
    "KEYCLOAK_CLIENT_ID"
    "KEYCLOAK_ADMIN_NEW_USERNAME"
    "KEYCLOAK_ADMIN_NEW_PASSWORD"
)

for var in "${required_vars[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: Required environment variable $var is not set"
        exit 1
    fi
done

# Wait for Keycloak to be ready
until curl -f "${KEYCLOAK_URL}/health/ready"; do
    echo "Waiting for Keycloak to start..."
    sleep 5
done

# Login to get admin token
echo "Logging in as admin..."
TOKEN=$(curl -d "client_id=${KEYCLOAK_ADMIN_CLIENT_ID}" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to obtain admin token"
    exit 1
fi

# Check if realm exists
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}")

if [ "$REALM_EXISTS" == "404" ]; then
    echo "Creating realm..."
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"realm":"'"${KEYCLOAK_REALM}"'", "enabled":true}' \
        "${KEYCLOAK_URL}/admin/realms"
else
    echo "Realm already exists, skipping creation..."
fi

# Check if client exists
CLIENT_EXISTS=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq '. | length')

if [ "$CLIENT_EXISTS" == "0" ]; then
    echo "Creating client..."
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "'"${KEYCLOAK_CLIENT_ID}"'",
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
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients"

    # Get client secret for the new client
    echo "Getting client secret..."
    CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq -r '.[0].id')
    CLIENT_SECRET=$(curl -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/$CLIENT_UUID/client-secret" | jq -r '.value')

    # Update .env file with client secret
    if [ -n "$CLIENT_SECRET" ]; then
        if ! grep -q "APP_KEYCLOAK_CLIENT_SECRET=" .env; then
            echo "APP_KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET" >> .env
            echo "Client secret added to .env file"
        fi
    else
        echo "Error: Failed to obtain client secret"
        exit 1
    fi
else
    echo "Client already exists, skipping creation..."
fi

# Check if admin user exists
USER_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_ADMIN_NEW_USERNAME}" | jq '. | length')

if [ "$USER_EXISTS" == "0" ]; then
    echo "Creating admin user..."
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "'"${KEYCLOAK_ADMIN_NEW_USERNAME}"'",
            "enabled": true,
            "credentials": [{
                "type": "password",
                "value": "'"${KEYCLOAK_ADMIN_NEW_PASSWORD}"'",
                "temporary": false
            }],
            "realmRoles": ["admin"]
        }' \
        "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users"
else
    echo "Admin user already exists, skipping creation..."
fi

# Setup service account roles
CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq -r '.[0].id')

SERVICE_ACCOUNT_USER=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients/$CLIENT_UUID/service-account-user" | jq -r '.id')

REALM_MANAGEMENT_CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=realm-management" | jq -r '.[0].id')

# Assign necessary roles for user management
curl -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '[
        {"id":"manage-users-role-id", "name":"manage-users"},
        {"id":"view-users-role-id", "name":"view-users"},
        {"id":"query-users-role-id", "name":"query-users"}
    ]' \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/$SERVICE_ACCOUNT_USER/role-mappings/clients/$REALM_MANAGEMENT_CLIENT_UUID"

echo "Initialization complete!"