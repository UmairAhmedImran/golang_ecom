package auth

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net/mail"
	"net/smtp"

	"github.com/UmairAhmedImran/ecom/config"
)

func GenerateOTP() string {
	var n uint32
	err := binary.Read(rand.Reader, binary.BigEndian, &n)
	if err != nil {
		panic(err) // Handle this error properly in production
	}
	log.Println("OTP: ", n)
	return fmt.Sprintf("%06d", n%1000000) // Ensures the OTP is always 6 digits
}
func SendOTPEmail(email, otp string) error {
	smtpHost := config.GetEnv("SMTP_HOST", "")
	smtpPort := config.GetEnv("SMTP_PORT", "")
	smtpUser := config.GetEnv("SMTP_USER", "")
	smtpPassword := config.GetEnv("SMTP_PASSWORD", "")

	// Validate SMTP configuration
	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPassword == "" {
		return fmt.Errorf("SMTP configuration is incomplete")
	}

	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)

	from := mail.Address{Name: "Umair", Address: config.GetEnv("SMTP_FROM", "")} // Replace with your verified email
	to := mail.Address{Name: "", Address: email}

	log.Println(config.GetEnv("SMTP_FROM", ""))

	subject := "Your OTP for Email Verification"
	body := fmt.Sprintf("Your OTP is: %s. It will expire in 10 minutes.", otp)
	// Build the message headers and body
	message := fmt.Sprintf(
    	"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
    	from.String(),        // "Umair <umairahmedimranbutt@gmail.com>"
    	to.String(),          // "<recipient@example.com>"
    	subject,
    	body,
)

	// Log the email details
	log.Printf("Attempting to send email to: %s", email)
	log.Printf("SMTP Host: %s, Port: %s", smtpHost, smtpPort)
	log.Printf("SMTP User: %s", smtpUser)
	log.Printf("From Email: %s", from.Address)

	// Send email using SMTP
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from.Address, []string{to.Address}, []byte(message))
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("Email sent successfully to: %s", email)
	return nil
}
