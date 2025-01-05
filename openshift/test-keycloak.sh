#!/bin/bash
set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "Error: .env file not found"
    exit 1
fi

echo "1. Getting admin token..."
TOKEN=$(curl -k -d "client_id=${KEYCLOAK_ADMIN_CLIENT_ID}" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to obtain admin token"
    exit 1
else
    echo "✓ Admin token obtained successfully"
fi

echo -e "\n2. Getting realm_admin user ID..."
USER_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_REALM_ADMIN_USERNAME}" \
    | jq -r '.[0].id')

if [ -z "$USER_ID" ]; then
    echo "Error: Could not find realm_admin user"
    exit 1
else
    echo "✓ Found realm_admin user with ID: $USER_ID"
fi

echo -e "\n3. Checking realm_admin roles..."
echo "Current roles assigned to realm_admin:"
curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm/composite" | jq -r '.[].name' | while read -r role; do
    echo "✓ Has role: $role"
done

echo -e "\n4. Testing realm_admin authentication..."
REALM_ADMIN_TOKEN=$(curl -k -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_REALM_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_REALM_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$REALM_ADMIN_TOKEN" ]; then
    echo "Error: Failed to obtain realm_admin token"
    exit 1
else
    echo "✓ Successfully authenticated as realm_admin"
fi

echo -e "\n5. Testing token introspection..."
INTROSPECTION_RESULT=$(curl -k -X POST \
    -d "token=${REALM_ADMIN_TOKEN}" \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token/introspect" | jq -r '.active')

if [ "$INTROSPECTION_RESULT" = "true" ]; then
    echo "✓ Token introspection successful"
else
    echo "Error: Token introspection failed"
fi

echo -e "\n6. Testing user management..."
echo "Creating test user..."
TEST_USER_RESPONSE=$(curl -k -X POST \
    -H "Authorization: Bearer ${REALM_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "testuser",
        "enabled": true,
        "credentials": [{
            "type": "password",
            "value": "test123",
            "temporary": false
        }]
    }' \
    -w "%{http_code}" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users")

if [ "$TEST_USER_RESPONSE" = "201" ] || [ "$TEST_USER_RESPONSE" = "409" ]; then
    echo "✓ User creation test passed (created or already exists)"
else
    echo "Error: Failed to create test user"
fi

echo "Retrieving test user..."
TEST_USER_GET=$(curl -k -H "Authorization: Bearer ${REALM_ADMIN_TOKEN}" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=testuser" | jq '. | length')

if [ "$TEST_USER_GET" -gt 0 ]; then
    echo "✓ Successfully retrieved test user"
else
    echo "Error: Could not retrieve test user"
fi

echo -e "\n7. Testing token refresh..."
echo "Getting fresh tokens..."
TOKEN_RESPONSE=$(curl -k -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${KEYCLOAK_REALM_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_REALM_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token")

REFRESH_TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.refresh_token')

if [ -z "$REFRESH_TOKEN" ] || [ "$REFRESH_TOKEN" = "null" ]; then
    echo "Error: Failed to obtain refresh token"
    exit 1
else
    echo "✓ Obtained refresh token"
fi

echo "Testing token refresh..."
REFRESH_RESPONSE=$(curl -k -X POST \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "grant_type=refresh_token" \
    -d "refresh_token=${REFRESH_TOKEN}" \
    "${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" | jq -r '.access_token')

if [ -n "$REFRESH_RESPONSE" ] && [ "$REFRESH_RESPONSE" != "null" ]; then
    echo "✓ Successfully refreshed token"
else
    echo "Error: Failed to refresh token"
fi

echo -e "\n8. Cleanup..."
echo "Removing test user..."
TEST_USER_ID=$(curl -k -H "Authorization: Bearer ${REALM_ADMIN_TOKEN}" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=testuser" | jq -r '.[0].id')

if [ -n "$TEST_USER_ID" ] && [ "$TEST_USER_ID" != "null" ]; then
    curl -k -X DELETE \
        -H "Authorization: Bearer ${REALM_ADMIN_TOKEN}" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${TEST_USER_ID}"
    echo "✓ Test user removed"
else
    echo "Warning: Could not find test user to remove"
fi

echo -e "\nPermission verification complete!"