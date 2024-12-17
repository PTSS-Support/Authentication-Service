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
3. Create a config file

for local development, create a `config.yaml` file in the root directory of the project with the following content:
```yaml
server:
  port: "8081"

keycloak:
  baseURL: "http://localhost:8080"
  realm: "master"         
  clientID: "admin-cli"
  adminUsername: "admin"
  adminPassword: "admin"
```

4. Start keycloak server
```bash
docker-compose up
```

5. Run the application
```bash
go run cmd/main.go
```

## API Testing
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
3. get user info
```bash
# Replace TOKEN with the access token from login response
curl -X GET http://localhost:8081/auth/me \
  -H "Authorization: Bearer TOKEN"
```

