package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gin/api"
	"gin/middleware"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupSimpleTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

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

func TestRegisterUser_InvalidInput(t *testing.T) {
	router := setupSimpleTestRouter()

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

	// Should return 400 for invalid input
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLoginUser_InvalidInput(t *testing.T) {
	router := setupSimpleTestRouter()

	// Test login with missing fields
	loginData := map[string]string{
		"email": "test@example.com",
		// Missing password
	}

	jsonData, _ := json.Marshal(loginData)
	req, _ := http.NewRequest("POST", "/auth/login", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 400 for invalid input
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestProtectedRoute_WithoutToken(t *testing.T) {
	router := setupSimpleTestRouter()

	// Test protected route without token
	req, _ := http.NewRequest("GET", "/protected", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 401 for missing token
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedRoute_WithInvalidToken(t *testing.T) {
	router := setupSimpleTestRouter()

	// Test protected route with invalid token
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 401 for invalid token
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedRoute_WithMalformedToken(t *testing.T) {
	router := setupSimpleTestRouter()

	// Test protected route with malformed token (missing Bearer prefix)
	req, _ := http.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "invalid-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return 401 for malformed token
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
