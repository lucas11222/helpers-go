package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"errors"
	"log"
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
	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello world :) running in the go version")
	})
	r.NoRoute(func(c *gin.Context) {
		c.JSON(404, gin.H{
			"success": false,
			"error":   "Page not found",
			"type":    "not_found",
			"message": "Not Found",
		})
	})
	r.GET("/error-test", func(c *gin.Context) {
		c.Error(errors.New("something went wrong"))
	})
	return r
}
