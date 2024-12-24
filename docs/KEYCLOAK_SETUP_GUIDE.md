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

If nothing works, cry and then ask for help. Thanks.