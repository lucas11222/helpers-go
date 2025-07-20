package mailer

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mailgun/mailgun-go/v5"
)

func Mailer(subject, body, recipient string) {
	// Create an instance of the Mailgun Client
	mg := mailgun.NewMailgun(os.Getenv("MAILGUN_API_KEY"))

	// When you have an EU domain, you must specify the endpoint:
	// err := mg.SetAPIBase(mailgun.APIBaseEU)

	sender := os.Getenv("MAILGUN_SENDER_EMAIL")

	// The message object allows you to add attachments and Bcc recipients
	message := mailgun.NewMessage(os.Getenv("MAILGUN_DOMAIN"), sender, subject, body, recipient)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// Send the message with a 10-second timeout
	resp, err := mg.Send(ctx, message)

	if err != nil {
		log.Fatal(err)
	}
	if os.Getenv("DB_ENV") == "production" {
		fmt.Printf("ID: %s Resp: %s\n", resp.ID, resp.Message)
	}
}
