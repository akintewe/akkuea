package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gin/api"
	"gin/config"
	"gin/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter() *gin.Engine {
	// Load test environment
	config.InitDB()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.Logger())

	// Public routes
	router.POST("/auth/register", api.RegisterUser)
	router.POST("/auth/login", api.LoginUser)

	// Protected routes
	protected := router.Group("/")
	protected.Use(middleware.JWTAuthMiddleware())
	{
		protected.GET("/protected", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Protected route accessed successfully"})
		})
		protected.GET("/auth/me", api.GetCurrentUser)
	}

	return router
}

func TestRegisterUser_Valid(t *testing.T) {
	router := setupTestRouter()

	// Test valid registration
	registerData := map[string]string{
		"name":     "Test User",
		"email":    "test@example.com",
		"password": "password123",
		"role":     "Student",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRegisterUser_Invalid(t *testing.T) {
	router := setupTestRouter()

	// Test invalid registration (missing fields)
	registerData := map[string]string{
		"name": "Test User",
		// Missing email, password, role
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLoginUser_Valid(t *testing.T) {
	router := setupTestRouter()

	// First register a user
	registerData := map[string]string{
		"name":     "Test User",
		"email":    "test@example.com",
		"password": "password123",
		"role":     "Student",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Now test login
	loginData := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}

	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLoginUser_Invalid(t *testing.T) {
	router := setupTestRouter()

	// Test login with wrong credentials
	loginData := map[string]string{
		"email":    "nonexistent@example.com",
		"password": "wrongpassword",
	}

	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedRoute_WithToken(t *testing.T) {
	router := setupTestRouter()

	// First register and login to get a token
	registerData := map[string]string{
		"name":     "Test User",
		"email":    "test@example.com",
		"password": "password123",
		"role":     "Student",
	}

	jsonData, _ := json.Marshal(registerData)
	req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Extract token from response
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	data := response["data"].(map[string]interface{})
	token := data["token"].(string)

	// Test protected route with token
	req, _ = http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRoleBasedAccess(t *testing.T) {
	router := setupTestRouter()

	// Test with different roles
	roles := []string{"Educator", "Student", "Designer"}

	for _, role := range roles {
		// Register user with specific role
		registerData := map[string]string{
			"name":     "Test " + role,
			"email":    "test" + role + "@example.com",
			"password": "password123",
			"role":     role,
		}

		jsonData, _ := json.Marshal(registerData)
		req, _ := http.NewRequest("POST", "/auth/register", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code, "Registration should succeed for role: "+role)

		// Login to get token
		loginData := map[string]string{
			"email":    "test" + role + "@example.com",
			"password": "password123",
		}

		jsonData, _ = json.Marshal(loginData)
		req, _ = http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")

		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Login should succeed for role: "+role)

		// Test protected route with token
		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		data := response["data"].(map[string]interface{})
		token := data["token"].(string)

		req, _ = http.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Protected route should be accessible for role: "+role)
	}
}
