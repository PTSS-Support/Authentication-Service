# Keycloak Setup and Initialization

This repository contains configuration and scripts for setting up and initializing a Keycloak instance in a Kubernetes environment, along with the necessary initialization scripts for realm and user setup.

This script initializes a Keycloak instance with required realm, client, roles, and admin users.

## Repository Structure

- `keycloak.yaml`: Kubernetes manifest for deploying Keycloak instance
- `init.sh`: Script for initializing Keycloak with realm, clients, and roles
- `test-keycloak.sh`: Script for testing Keycloak setup and permissions
- `.env.example`: Template for environment variables

## Deployment Instructions

1. Deploy Keycloak to OpenShift:
   ```bash
   oc apply -f keycloak.yaml
   ```
   This will create a Keycloak instance with:
    - HTTP enabled
    - Custom hostname configuration
    - Health checks configured
    - Edge proxy settings

2. Create the Keycloak route:
   ```bash
   oc apply -f keycloak-route.yaml
   ```

3. Verify the deployment:
   ```bash
   oc get keycloak -n hotel-dev
   oc get pods -n hotel-dev
   oc get route -n hotel-dev
   ```

4. Wait for the route to be ready and note the URL - you'll need this for your `.env` file's `KEYCLOAK_BASE_URL`.

## Setup Instructions

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Fill in the `.env` file:
    - `KEYCLOAK_BASE_URL`: URL of your Keycloak instance (e.g., `https://keycloak-hotel-dev.apps.inholland.hcs-lab.nl`)
    - `KEYCLOAK_ADMIN_USERNAME`: Keep as `temp-admin`
    - `KEYCLOAK_ADMIN_PASSWORD`: Get from Keycloak operator secrets (created when instance is deployed)
    - `KEYCLOAK_REALM_ADMIN_USERNAME`: Keep as `realm_admin`
    - `KEYCLOAK_REALM_ADMIN_PASSWORD`: Choose a secure password

3. Run the initialization script:
   ```bash
   ./init.sh
   ```

   The script will:
    - Create a new admin user using credentials from `.env`
    - Remove the temporary admin account
    - Setup realm, client, roles and realm admin
    - Generate client secret and append to `.env`

4. After successful execution, copy the generated `KEYCLOAK_CLIENT_SECRET` from `.env` to your service's secrets.

5. Verify the setup by running the test script:
   ```bash
   ./test-keycloak.sh
   ```

   The test script will verify:
    - Admin authentication
    - Realm admin permissions
    - Token management
    - User management capabilities
    - Token refresh functionality

## Troubleshooting

If the test script fails:
1. Check if Keycloak is properly deployed and accessible
2. Verify all environment variables in `.env` are correctly set
3. Ensure the Keycloak instance is healthy using the health endpoints
4. Check the Keycloak logs for any errors:
   ```bash
   oc logs -n hotel-dev deployment/hotel-keycloak
   ```

You can also check the Keycloak operator logs:
   ```bash
   oc logs -n hotel-dev deployment/keycloak-operator
   ```

## Important Notes

- The `temp-admin` account is automatically replaced with permanent admin credentials
- Keep your `.env` file secure and never commit it to version control
- Client secret is automatically generated and added to `.env` after initial setup