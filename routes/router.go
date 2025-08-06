package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"errors"
	"log"
	"main/utills/authmanager"
	"net/http"
	"os"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next() // Step1: Process the request first.

		// Step2: Check if any errors were added to the context
		if len(c.Errors) > 0 {
			// Step3: Use the last error
			err := c.Errors.Last().Err

			// Step4: Respond with a generic error message
			c.JSON(http.StatusInternalServerError, map[string]any{
				"success": false,
				"message": err.Error(),
				"type":    "unknown",
			})
		}

		// Any other steps if no errors are found
	}
}

func SetupRouter() *gin.Engine {
	// Disable Console Color
	// gin.DisableConsoleColor()
	r := gin.Default()
	env := godotenv.Load()
	r.Use(ErrorHandler())
	if env != nil {
		log.Fatal("Error loading .env file. Check the .env for any formating errors.")
	}
	if os.Getenv("DB_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r.SetTrustedProxies([]string{"192.168.1.2"})
	// this is for testing
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"success": true,
			"messege": "OK",
			"version": "1.0.0",
		})
	})
	r.GET("/v2/accounts/me", func(c *gin.Context) {
		token := c.GetHeader("Authorization") // cleaner than c.Request.Header.Get()
		if token == "" {
			c.JSON(400, gin.H{
				"messege": "The token is empty",
				"success": false,
				"type":    "missing_token",
			})
			return
		}
		userJSON, err := authmanager.GetUserByToken(token)
		if err != nil {
			c.JSON(401, gin.H{
				"messege": "The token is invalid or expired.",
				"success": false,
				"type":    "invalid_token",
			})
			return
		}

		c.Data(200, "application/json", []byte(userJSON))
	})
	type SignupRequest struct {
		Name     string `json:"name"`
		Username string `json:"Username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	r.POST("/v2/accounts/signup", func(c *gin.Context) {
		var req SignupRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{
				"messege": "Invalid JSON",
				"type":    "invalid_json",
				"success": false,
			})
			return
		}

		if req.Email == "" || req.Password == "" {
			c.JSON(400, gin.H{
				"error":   "Please provide all required fields.",
				"type":    "missing_fields",
				"success": false,
			})
			return
		}
		token, err := authmanager.CreateAccount(req.Name, req.Username, req.Email, req.Password)
		if err == nil {
			c.Error(errors.New("An unknown error occurred while creating the account. This is when the prosses of creating the token has failed."))
			return
		}
		c.JSON(200, gin.H{
			"success": true,
			"token":   token,
		})
	})
	type loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	r.POST("/v2/accounts/login", func(c *gin.Context) {
		var req loginRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{
				"messege": "Invalid JSON",
				"type":    "invalid_json",
				"success": false,
			})
			return
		}

		if req.Email == "" || req.Password == "" {
			c.JSON(400, gin.H{
				"error":   "Please provide all required fields.",
				"type":    "missing_fields",
				"success": false,
			})
			return
		}
		token, err := authmanager.JWTCreateToken(req.Email)
		if err == nil {
			c.Error(errors.New("An unknown error occurred while creating the token."))
			return
		}
		hash, err := authmanager.GetUserByEmailHash(req.Email, true)
		password := authmanager.CheckPassword(req.Password, hash.PasswordHash)
		if password != false {
			c.JSON(500, gin.H{
				"success": false,
				"type":    "invalid_credentials",
				"messege": "The password is invalid.",
			})
			return
		}
		if err == nil {
			c.Error(errors.New("An unknown error occurred while checking the password."))
		}
		c.JSON(200, gin.H{
			"success": true,
			"token":   token,
		})
	})
	type deleteRequest struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	r.DELETE("/v2/accounts/delete", func(c *gin.Context) {
		var req deleteRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{
				"messege": "Invalid JSON",
				"type":    "invalid_json",
				"success": false,
			})
			return
		}

		if req.Password == "" {
			c.JSON(400, gin.H{
				"error":   "Please provide all required fields.",
				"type":    "missing_fields",
				"success": false,
			})
			return
		}
		hash, err := authmanager.GetUserByTokenHash(c.GetHeader("Authorization"))
		password := authmanager.CheckPassword(req.Password, hash.PasswordHash)
		if password != false {
			c.JSON(500, gin.H{
				"success": false,
				"type":    "invalid_credentials",
				"messege": "The password is invalid.",
			})
			return
		}
		if err == nil {
			c.Error(errors.New("Cannot get user by token"))
		}
		authmanager.DeleteAccount(req.Email)
		c.JSON(200, gin.H{
			"success": true,
			"message": "Account deleted successfully",
		})
	})
	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello world :) running in the go version!")
	})
	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"success": false,
			"error":   "Page not found",
			"type":    "not_found",
			"message": "Not Found",
		})
	})
	return r
}
