# Authentication Service
Authentication and authorization service for PTSS Support, built with Go and Keycloak.

### Framework Choices
- **Gin**: High-performance HTTP web framework
- **Viper**: Configuration management
- **Keycloak**: Enterprise-grade identity management

### Getting Started
1. Clone the repository
```bash
git clone https://github.com/ptss-support/authentication-service.git
cd authentication-service

```

2. Install dependencies
```bash
go mod tidy
```
3. Configure Environment Variables

For local development, create a `.env` file in the root directory of the project. You can use the provided [`.env.example`](./.env.example) as a template.

4. Start keycloak server
```bash
docker compose up
```

5. Configure Keycloak
   Follow the [Keycloak Setup Guide](docs/KEYCLOAK_SETUP_GUIDE.md) to:
   - Create a custom realm
   - Configure the required client
   - Set up proper authentication flows
   
   This is a crucial step for the service to work correctly.

6. Run the application
```bash
go run cmd/main.go
```

## API Testing

> [!CAUTION]
> Need to be adjusted!

1. Create a new user
```bash
curl -X POST http://localhost:8081/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "firstName": "John",
    "lastName": "Doe",
    "role": "patient"
  }'
```
2. Login
```bash
curl -X POST http://localhost:8081/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```
3. Get user info
```bash
# Replace TOKEN with the access token from login response
curl -X GET http://localhost:8081/auth/me \
  -H "Authorization: Bearer TOKEN"
```

