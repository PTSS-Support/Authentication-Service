#!/bin/sh
set -e

USE_DOCKER=${USE_DOCKER:-false}

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

# Login to get temp_admin token
echo "Logging in as admin..."
TOKEN=$(curl -k -d "client_id=${KEYCLOAK_ADMIN_CLIENT_ID}" \
    -d "username=${KEYCLOAK_ADMIN_USERNAME}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token" | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "Error: Failed to obtain admin token"
    exit 1
fi

# Check if realm exists
REALM_EXISTS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}")

echo "Realm check result: $REALM_EXISTS"


if [ "$REALM_EXISTS" = "404" ]; then
    echo "Creating realm..."
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
              "realm":"'"${KEYCLOAK_REALM}"'",
              "enabled":true,
              "revokeRefreshToken":true,
              "accessTokenLifespan":1200,
              "ssoSessionIdleTimeout":2592000,
              "ssoSessionMaxLifespan":2592000,
              "offlineSessionIdleTimeout":2592000,
              "offlineSessionMaxLifespan":2592000,
              "refreshTokenMaxReuse":20,
              "accessTokenLifespanForImplicitFlow":1200
                }' \
        "${KEYCLOAK_BASE_URL}/admin/realms"

    echo "Configuring user profile attributes..."
    # shellcheck disable=SC2016
    curl -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
                  "attributes": [
                      {
                          "name": "userId",
                          "displayName": "User ID",
                          "required": {
                              "roles": ["user"]
                          },
                          "permissions": {
                              "view": ["admin", "user"],
                              "edit": ["admin"]
                          },
                          "multivalued": false,
                          "validations": {
                              "length": { "min": 1, "max": 255 }
                          }
                      },
                      {
                          "name": "username",
                          "displayName": "${username}",
                          "validations": {
                              "length": {
                                  "min": 3,
                                  "max": 255
                              },
                              "username-prohibited-characters": {},
                              "up-username-not-idn-homograph": {}
                          },
                          "permissions": {
                              "view": ["admin"],
                              "edit": ["admin", "user"]
                          },
                          "multivalued": false
                      },
                      {
                          "name": "email",
                          "displayName": "${email}",
                          "validations": {
                              "email": {},
                              "length": {
                                  "max": 255
                              }
                          },
                          "required": {
                              "roles": ["user"]
                          },
                          "permissions": {
                              "view": ["admin"],
                              "edit": ["admin", "user"]
                          },
                          "multivalued": false
                      },
                      {
                          "name": "firstName",
                          "displayName": "${firstName}",
                          "validations": {
                              "length": {
                                  "max": 255
                              },
                              "person-name-prohibited-characters": {}
                          },
                          "required": {
                              "roles": ["user"]
                          },
                          "permissions": {
                              "view": ["admin", "user"],
                              "edit": ["admin", "user"]
                          },
                          "multivalued": false
                      },
                      {
                          "name": "lastName",
                          "displayName": "${lastName}",
                          "validations": {
                              "length": {
                                  "max": 255
                              },
                              "person-name-prohibited-characters": {}
                          },
                          "required": {
                              "roles": ["user"]
                          },
                          "permissions": {
                              "view": ["admin", "user"],
                              "edit": ["admin", "user"]
                          },
                          "multivalued": false
                      },
                      {
                          "name": "groupId",
                          "displayName": "group id",
                          "permissions": {
                              "edit": ["admin", "user"],
                              "view": ["user", "admin"]
                          },
                          "multivalued": false,
                          "annotations": {},
                          "validations": {}
                      },
                      {
                          "name": "role",
                          "displayName": "Role",
                          "permissions": {
                              "edit": ["admin"],
                              "view": ["user", "admin"]
                          },
                          "multivalued": false,
                          "annotations": {},
                          "validations": {
                              "length": { "min": 1, "max": 255 }
                          }
                      },
                      {
                          "name": "hasPin",
                          "displayName": "Has PIN",
                          "permissions": {
                              "edit": ["admin", "user"],
                              "view": ["user", "admin"]
                          },
                          "multivalued": false,
                          "annotations": {},
                          "validations": {}
                      },
                      {
                          "name": "pin",
                          "displayName": "PIN",
                          "permissions": {
                              "edit": ["admin", "user"],
                              "view": ["user", "admin"]
                          },
                          "multivalued": false,
                          "annotations": {},
                          "validations": {
                              "length": { "min": 1, "max": 255 }
                          }
                      }
                  ],
                  "groups": [
                      {
                          "name": "user-metadata",
                          "displayHeader": "User metadata",
                          "displayDescription": "Attributes, which refer to user metadata"
                      }
                  ]
              }'  \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/profile"
else
    echo "Realm already exists, skipping creation..."
fi

# Check if client exists
CLIENT_EXISTS=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq '. | length')

if [ "$CLIENT_EXISTS" = "0" ]; then
    echo "Creating client..."
    curl -k -X POST \
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

    echo "Client created!"

    CLIENT_UUID=$(curl -k -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq -r '.[0].id')

    # Create user-details client scope
    echo "Creating client scope..."
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "user-details",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes"

    # Get the scope ID
    SCOPE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
        | jq -r '.[] | select(.name=="user-details") | .id')

    # Add user ID mapper
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "user-id-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "userId",
                "claim.name": "userId",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "realm-roles",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "multivalued": "true",
                "claim.name": "roles",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Add firstName mapper
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "first-name",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "user.attribute": "firstName",
                "claim.name": "first_name",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Add lastName mapper
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "last-name",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "user.attribute": "lastName",
                "claim.name": "last_name",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Add groupId mapper
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "group-id",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "groupId",
                "claim.name": "group_id",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Add role mapper
    curl -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "role-attribute-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "role",
                "claim.name": "role",
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Add hasPin mapper
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "has-pin-mapper",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {
                "user.attribute": "hasPin",
                "claim.name": "has_pin",
                "jsonType.label": "boolean",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
                "access.tokenResponse.claim": "false",
                "refresh.token.claim": "true"
            }
        }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes/${SCOPE_ID}/protocol-mappers/models"

    # Assign scope to client
    curl -k -X PUT \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/default-client-scopes/${SCOPE_ID}"

    echo "Client scope created and assigned to client!"
fi

# Get client UUID (whether newly created or existing)
echo "Getting client UUID..."
CLIENT_UUID=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients?clientId=${KEYCLOAK_CLIENT_ID}" | jq -r '.[0].id')


# Finally assign scope to client
curl -k -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/default-client-scopes/${SCOPE_ID}"

if [ "$CLIENT_EXISTS" = "0" ]; then
    echo "Getting client secret..."
    CLIENT_SECRET=$(curl -k -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/$CLIENT_UUID/client-secret" | jq -r '.value')

    # Create required realm roles if they don't exist
    echo "Creating realm roles..."
    ROLES="manage-users view-users create-user validate-tokens manage-realm view-realm manage-clients view-clients manage-authorization token-exchange impersonation"

    for ROLE in $ROLES; do
        ROLE_EXISTS=$(curl -k -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}")

        if [ "$ROLE_EXISTS" = "404" ]; then
            curl -k -X POST \
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

    # Create custom roles for application specific roles
    CUSTOM_ROLES="admin family_member primary_relative patient healthcare_professional"

    for ROLE in $CUSTOM_ROLES; do
        ROLE_EXISTS=$(curl -k -s -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}")

        if [ "$ROLE_EXISTS" = "404" ]; then
            curl -k -X POST \
                -H "Authorization: Bearer $TOKEN" \
                -H "Content-Type: application/json" \
                -d '{
                    "name": "'"${ROLE}"'",
                    "description": "'"${ROLE}"' role"
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
USER_EXISTS=$(curl -k -s -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_REALM_ADMIN_USERNAME}" | jq '. | length')

if [ "$USER_EXISTS" = "0" ]; then
    echo "Creating admin user..."
    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
               "username": "'"${KEYCLOAK_REALM_ADMIN_USERNAME}"'",
               "enabled": true,
               "emailVerified": true,
               "email": "realm_admin@example.com",
               "firstName": "Realm",
               "lastName": "Admin",
               "credentials": [{
                   "type": "password",
                   "value": "'"${KEYCLOAK_REALM_ADMIN_PASSWORD}"'",
                   "temporary": false
               }],
               "requiredActions": [],
               "realmRoles": ["admin manage-users view-users create-user validate-tokens"]
           }' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users"
    # Get the user ID
    USER_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${KEYCLOAK_REALM_ADMIN_USERNAME}" \
        | jq -r '.[0].id')

    # Assign realm roles to the user
    echo "Assigning roles to admin user..."
    for ROLE in $ROLES; do
        ROLE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}" \
            | jq -r '.id')

        curl -k -X POST \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '[{
                "id": "'"${ROLE_ID}"'",
                "name": "'"${ROLE}"'"
            }]' \
            "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm"
    done

    curl -k -X POST \
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


# removing the default scopes
# email scope
EMAIL_SCOPE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
    | jq -r '.[] | select(.name=="email") | .id')

if [ -n "$EMAIL_SCOPE_ID" ]; then
    echo "Removing email scope from client..."
    curl -k -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/default-client-scopes/${EMAIL_SCOPE_ID}"
fi

# Remove profile scope (contains preferred_username)
PROFILE_SCOPE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
    | jq -r '.[] | select(.name=="profile") | .id')

if [ -n "$PROFILE_SCOPE_ID" ]; then
    echo "Removing profile scope from client..."
    curl -k -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/default-client-scopes/${PROFILE_SCOPE_ID}"
fi

# Remove roles scope (contains realm_access)
ROLES_SCOPE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/client-scopes" \
    | jq -r '.[] | select(.name=="roles") | .id')

if [ -n "$ROLES_SCOPE_ID" ]; then
    echo "Removing roles scope from client..."
    curl -k -X DELETE \
        -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/default-client-scopes/${ROLES_SCOPE_ID}"
fi

# Setup service account permissions
echo "Setting up service account permissions..."
SERVICE_ACCOUNT_USER=$(curl -k -H "Authorization: Bearer $TOKEN" \
    "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/clients/${CLIENT_UUID}/service-account-user" | jq -r '.id')

# Assign roles to the service account
for ROLE in $ROLES; do
    ROLE_ID=$(curl -k -H "Authorization: Bearer $TOKEN" \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE}" \
        | jq -r '.id')

    curl -k -X POST \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '[{
            "id": "'"${ROLE_ID}"'",
            "name": "'"${ROLE}"'"
        }]' \
        "${KEYCLOAK_BASE_URL}/admin/realms/${KEYCLOAK_REALM}/users/${SERVICE_ACCOUNT_USER}/role-mappings/realm"
done


echo "Initialization complete!"