#!/bin/sh
set -e

USE_DOCKER=${USE_DOCKER:-true}

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

# Required environment variables check
check_required_var() {
    if [ -z "$(eval echo \$$1)" ]; then
        echo "Error: Required environment variable $1 is not set"
        exit 1
    fi
}

# Check all required variables
check_required_var "KEYCLOAK_BASE_URL"
check_required_var "KEYCLOAK_ADMIN_CLIENT_ID"
check_required_var "KEYCLOAK_ADMIN_USERNAME"
check_required_var "KEYCLOAK_ADMIN_PASSWORD"
check_required_var "KEYCLOAK_REALM"
check_required_var "KEYCLOAK_CLIENT_ID"
check_required_var "KEYCLOAK_REALM_ADMIN_USERNAME"
check_required_var "KEYCLOAK_REALM_ADMIN_PASSWORD"

if [ "$USE_DOCKER" = "true" ]; then
    KEYCLOAK_BASE_URL="http://keycloak:8080"
    echo "Running in Docker mode, using URL: ${KEYCLOAK_BASE_URL}"
fi

# Wait for Keycloak to be ready
until curl -f "${KEYCLOAK_BASE_URL}/health/ready"; do
    echo "Trying to connect to Keycloak at: ${KEYCLOAK_BASE_URL}/health/ready"
    echo "Waiting for Keycloak to start..."
    sleep 5
done

# Login to get admin token
echo "Logging in as admin..."
TOKEN=$(curl -d "client_id=${KEYCLOAK_ADMIN_CLIENT_ID}" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to obtain admin token"
    exit 1
fi

# Check if realm exists
REALM_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}")

if [ "$REALM_EXISTS" = "404" ]; then
    echo "Creating realm..."
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"realm":"'"${KEYCLOAK_REALM}"'", "enabled":true}' \
        "${KEYCLOAK_BASE_URL}/admin/realms"
else
    echo "Realm already exists, skipping creation..."
fi

# Check if client exists
CLIENT_EXISTS=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq '. | length')

if [ "$CLIENT_EXISTS" = "0" ]; then
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
            "webOrigins": ["*"],
            "clientAuthenticatorType": "client-secret"
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients"
fi

# Get client UUID (whether newly created or existing)
echo "Getting client UUID..."
CLIENT_UUID=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq -r '.[0].id')

if [ "$CLIENT_EXISTS" = "0" ]; then
    echo "Getting client secret..."
    CLIENT_SECRET=$(curl -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/$CLIENT_UUID/client-secret" | jq -r '.value')

    # Create required realm roles if they don't exist
    echo "Creating realm roles..."
    ROLES="manage-users view-users create-user validate-tokens"

    for ROLE in $ROLES; do
        ROLE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}")

        if [ "$ROLE_EXISTS" = "404" ]; then
            curl -X POST \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d '{
                    "name": "'"${ROLE}"'",
                    "description": "Permission to '"${ROLE}"'"
                }' \
                "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles"
            echo "Created role: ${ROLE}"
        fi
    done

    # Update .env file with client secret
    if [ -n "$CLIENT_SECRET" ]; then
        if ! grep -q "KEYCLOAK_CLIENT_SECRET=" .env; then
            echo "KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET" >> .env
            echo "Client secret added to .env file"
        fi
    else
        echo "Error: Failed to obtain client secret"
        exit 1
    fi
fi

# Check if admin user exists
USER_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_REALM_ADMIN_USERNAME}" | jq '. | length')

if [ "$USER_EXISTS" = "0" ]; then
    echo "Creating admin user..."
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "'"${KEYCLOAK_REALM_ADMIN_USERNAME}"'",
            "enabled": true,
            "credentials": [{
                "type": "password",
                "value": "'"${KEYCLOAK_REALM_ADMIN_PASSWORD}"'",
                "temporary": false
            }],
            "realmRoles": ["admin"]
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users"
    # Get the user ID
    USER_ID=$(curl -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_REALM_ADMIN_USERNAME}" \
        | jq -r '.[0].id')

    # Assign realm roles to the user
    echo "Assigning roles to admin user..."
    for ROLE in $ROLES; do
        ROLE_ID=$(curl -H "Authorization: Bearer $TOKEN" \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}" \
            | jq -r '.id')

        curl -X POST \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '[{
                "id": "'"${ROLE_ID}"'",
                "name": "'"${ROLE}"'"
            }]' \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm"
    done

    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '[{
            "id": "admin",
            "name": "admin"
        }]' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm"
else
    echo "Admin user already exists, skipping creation..."
fi


# Setup service account permissions
echo "Setting up service account permissions..."
SERVICE_ACCOUNT_USER=$(curl -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/service-account-user" | jq -r '.id')

# Assign roles to the service account
for ROLE in $ROLES; do
    ROLE_ID=$(curl -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}" \
        | jq -r '.id')

    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '[{
            "id": "'"${ROLE_ID}"'",
            "name": "'"${ROLE}"'"
        }]' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${SERVICE_ACCOUNT_USER}/role-mappings/realm"
done


echo "Initialization complete!"