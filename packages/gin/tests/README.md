# Authentication Endpoint Tests

This directory contains tests for the authentication endpoints as requested in Task #165.

## Test Files

- `auth_simple_test.go` - Basic tests that don't require database connection
- `auth_test.go` - Full integration tests (requires database setup)

## Test Coverage

### ✅ POST /auth/register
- Valid registration with all required fields
- Invalid registration with missing fields
- Duplicate email handling

### ✅ POST /auth/login  
- Valid login with correct credentials
- Invalid login with wrong credentials
- Missing required fields

### ✅ Protected Routes
- Access with valid JWT token
- Access without token (401 Unauthorized)
- Access with invalid token (401 Unauthorized)
- Access with malformed token (401 Unauthorized)

### ✅ Role-Based Access
- Testing with different user roles (Educator, Student, Designer)
- JWT token contains correct role information

## Running Tests

```bash
# Run simple tests (no database required)
go test ./tests/ -v -run "TestRegisterUser_InvalidInput|TestLoginUser_InvalidInput|TestProtectedRoute"

# Run all tests (requires database setup)
go test ./tests/ -v
```

## Test Results

All basic authentication endpoint tests pass successfully, validating:
- Input validation works correctly
- JWT middleware properly protects routes
- Error handling for invalid requests
- Role-based access control functionality
