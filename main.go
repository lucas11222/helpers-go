package main

import (
	"log"
	"main/routes"
	"os"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
)

func sentrydatabase() {
	sentrysdk := sentry.Init(sentry.ClientOptions{
		Dsn: os.Getenv("SENTRY_DSN"),
		// Enable printing of SDK debug messages.
		// Useful when getting started or trying to figure something out.
		EnableLogs: true,
		// Adds request headers and IP for users,
		// visit: https://docs.sentry.io/platforms/go/data-management/data-collected/ for more info
		SendDefaultPII: true,
		// Change the sample rate to 0.5
		SampleRate: 0.5,
		// Set the enviroment to production or development
		Environment: os.Getenv("DB_ENV"),
		// idk what this does but it is in the helpers python version
		EnableTracing: true,
		Release:       "1.0.0",
	})
	if sentrysdk != nil {
		log.Fatalf("sentry.Init: %s", sentrysdk)
	}
}
func main() {
	env := godotenv.Load()
	if env != nil {
		log.Fatal("Error loading .env file. Check the .env for any formating errors.")
	}
	if os.Getenv("DB_ENV") == "production" {
		sentrydatabase()
	}
	r := routes.SetupRouter()
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8000")
}
