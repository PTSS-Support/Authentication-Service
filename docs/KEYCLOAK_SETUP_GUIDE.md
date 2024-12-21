[Go back to README](./../README.md)
# Keycloak Setup Guide for PTSS Support

This guide walks you through the necessary steps to configure Keycloak for the PTSS Support Authentication Service.

## Initial Setup

1. Access the Keycloak Admin Console:
   - Open your browser and navigate to `http://localhost:8080/admin`
   - Login with the default credentials:
     - Username: `admin`
     - Password: `admin`

## Create Custom Realm

1. Create a new realm for PTSS Support:
   - Click on the dropdown in the top-left corner (default shows "master")
   - Click "Create Realm"
   - Set Name to: `ptss-support`
   - Click "Create"

## Create Client for User Operations

1. In the `ptss-support` realm, create a new client:
   - Go to "Clients" in the left sidebar
   - Click "Create client"
   
2. Set basic client settings:
   - Client type: `OpenID Connect`
   - Client ID: `identity-service`
   - Click "Next"

3. Configure capability config:
   - Client authentication: `ON` (Enable client authentication)
   - Authentication flow:
     - Standard flow: `ON` (Enable OAuth2's Authorization Code flow)
     - Direct access grants: `ON` (Enable Resource Owner Password Credentials)
   - Click "Next"

4. Configure login settings:
   - Valid redirect URIs: Add `http://localhost:8081/*`
   - Web origins: Add `http://localhost:8081`
   - Click "Save"

5. Get client secret:
   - Go to the "Credentials" tab
   - Copy the Client secret value
   - Save this for your `config.yaml`

## Configure Admin Access

1. Admin CLI client is already configured in the master realm
2. Note: Keep using the master realm for admin operations

## Security Recommendations

1. Production Environment:
   - Change default admin password
   - Use HTTPS for all endpoints
   - Configure appropriate CORS settings
   - Enable email verification
   - Set up proper SSL/TLS certificates
   - Configure appropriate session timeouts

2. Client Security:
   - Restrict redirect URIs to known applications
   - Enable client authentication
   - Use appropriate scopes
   - Configure proper token settings

3. User Security:
   - Configure password policies
   - Enable MFA where appropriate
   - Set up proper role mappings

## Troubleshooting

Common issues and solutions:

1. Invalid credentials error:
   - Verify the realm name matches exactly
   - Ensure client secret is correct
   - Check if user exists in correct realm

2. Unauthorized client:
   - Verify Direct Access Grants is enabled
   - Check client authentication settings
   - Verify client secret is correct

3. Invalid redirect URI:
   - Check the configured Valid Redirect URIs
   - Ensure Web Origins are properly set

## Next Steps

After completing this setup:

1. Update your `config.yaml` with:
   - The correct realm name (`ptss-support`)
   - The client secret from the identity-service client
   - Keep admin credentials for administrative operations

2. Test the setup with the provided API endpoints
3. Configure additional security measures as needed