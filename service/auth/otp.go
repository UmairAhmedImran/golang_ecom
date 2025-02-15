package auth

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
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

// func SendOTPEmail(email, otp string) error {
// 	// SMTP settings
// 	smtpHost := config.GetEnv("SMTP_HOST", "")
// 	smtpPort := config.GetEnv("SMTP_PORT", "")
// 	to := email
// 	smtpUser := config.GetEnv("SMTP_USER", "")
// 	smtpPassword := config.GetEnv("SMTP_PASSWORD", "")

// 	auth := smtp.PlainAuth("", smtpUser, smtpPassword, smtpHost)

// 	subject := "Your OTP for Email Verification"
// 	body := fmt.Sprintf("Your OTP is: %s. It will expire in 10 minutes.", otp)
// 	message := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

// 	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, []string{to}, []byte(message))
// 	if err != nil {
// 		return err
// 	}
// 	log.Println("OTP sent to: ", email)

//		return nil
//	}
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

	subject := "Your OTP for Email Verification"
	body := fmt.Sprintf("Your OTP is: %s. It will expire in 10 minutes.", otp)
	message := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

	// Log the email details
	log.Printf("Attempting to send email to: %s", email)
	log.Printf("SMTP Host: %s, Port: %s", smtpHost, smtpPort)
	log.Printf("SMTP User: %s", smtpUser)

	// Send the email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUser, []string{email}, []byte(message))
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Printf("Email sent successfully to: %s", email)
	return nil
}
