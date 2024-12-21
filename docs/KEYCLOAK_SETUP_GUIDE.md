[Go back to README](./../README.md)
# Keycloak Setup Guide for PTSS Support

This guide walks you through the steps to configure Keycloak for the PTSS Support Authentication Service using the provided automation scripts. The process is simplified and uses a .env file for configuration.

## Prerequisites

Before proceeding, ensure you have the following:

- Docker and Docker Compose installed on your machine
- The provided `docker-compose.yml`, `.env`, and `keycloak-init.sh` files

## Setup

1. Update the `.env` file with your desired configuration values. The file should include the following variables:

   ```
   # Go Server Configuration
   SERVER_PORT=8081

   # Keycloak Configuration 
   KEYCLOAK_BASE_URL=http://localhost:8080
   KEYCLOAK_REALM=ptss-support

   # Keycloak Admin Operations
   KEYCLOAK_ADMIN_CLIENT_ID=admin-cli
   KEYCLOAK_ADMIN_USERNAME=admin  
   KEYCLOAK_ADMIN_PASSWORD=admin
   KEYCLOAK_REALM_ADMIN_USERNAME=realm_admin
   KEYCLOAK_REALM_ADMIN_PASSWORD=realm_admin_pw

   # Keycloak User Operations 
   KEYCLOAK_CLIENT_ID=authentication-service
   ```

2. Run the following command to start Keycloak and run the initialization script:

   ```
   docker-compose up -d
   ```

   This will:
   - Start a PostgreSQL database container
   - Start a Keycloak container
   - Run the `keycloak-init.sh` script to initialize Keycloak with the configuration from the `.env` file

3. After the containers are up and the initialization is complete, you can access the Keycloak Admin Console at `http://localhost:8080/admin` using the admin credentials specified in the `.env` file.

4. The initialization script will also output the `KEYCLOAK_CLIENT_SECRET` for the `authentication-service` client. This value will be added to your `.env` file automatically.

## Keycloak Configuration Details

The `keycloak-init.sh` script automates the following configuration steps:

1. Creates the `ptss-support` realm if it doesn't exist
2. Creates the `authentication-service` client with the following settings:
   - Client authentication enabled
   - Standard flow enabled
   - Direct access grants enabled
   - Service accounts enabled
   - Valid redirect URIs set to `*`
   - Web origins set to `*`
3. Creates the required realm roles: `manage-users`, `view-users`, `create-user`, `validate-tokens`
4. Creates an admin user with the username and password specified in the `.env` file and assigns the necessary roles
5. Sets up service account permissions for the `authentication-service` client

## Security Recommendations

Refer to the security recommendations mentioned in the previous guide. Additionally:

- Ensure the `.env` file is not committed to version control and is securely stored
- Restrict the `Valid Redirect URIs` and `Web Origins` settings to known applications in production

## Troubleshooting

If you encounter any issues during the setup process, first check the logs of the `init-keycloak` container:

```bash
docker-compose logs init-keycloak
```
or if you want to see why a pod might not be healthy or anything of the sort:
```bash
 docker inspect keycloak | grep -A 20 Health   
```

Common issues and solutions:

1. Script fails due to missing `.env` file:
   - Ensure the `.env` file exists in the same directory as the `docker-compose.yml` file
   - Verify that the `.env` file has the correct variable names and values

2. Containers fail to start:
   - Check if the required ports (8080 for Keycloak, 5432 for PostgreSQL) are not in use by other applications
   - Ensure you have the latest versions of Docker and Docker Compose

If the issues persist, refer to the Keycloak documentation or seek further assistance.

## Next Steps

After completing the setup:

1. Verify that the `KEYCLOAK_CLIENT_SECRET` has been added to your `.env` file
2. Test the setup with the provided API endpoints
3. Configure additional security measures as needed

Please let me know if you have any further questions!
## Prerequisites

Before proceeding, ensure you have the following:

- Docker and Docker Compose installed on your machine
- The provided docker-compose.yml, .env (which you can create with .env.example), and keycloak-init.sh files

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