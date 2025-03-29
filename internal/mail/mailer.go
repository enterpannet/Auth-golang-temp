package mail

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/example/auth-service/config"
	"gopkg.in/mail.v2"
)

// Mailer handles email operations
type Mailer struct {
	Config *config.Config
	dialer *mail.Dialer
}

// Email represents an email to be sent
type Email struct {
	To          string
	Subject     string
	Body        string
	IsHTML      bool
	ReplyTo     string
	Attachments []string
}

// NewMailer creates a new mailer service
func NewMailer(cfg *config.Config) *Mailer {
	dialer := mail.NewDialer(
		cfg.Mail.Host,
		cfg.Mail.Port,
		cfg.Mail.Username,
		cfg.Mail.Password,
	)

	// Set TLS configuration
	dialer.SSL = cfg.Mail.UseSSL
	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         cfg.Mail.Host,
	}

	if cfg.Mail.UseTLS {
		dialer.StartTLSPolicy = mail.MandatoryStartTLS
	}

	// Set a timeout
	dialer.Timeout = 10 * time.Second

	return &Mailer{
		Config: cfg,
		dialer: dialer,
	}
}

// Send sends an email
func (m *Mailer) Send(email Email) error {
	// If mail service is disabled, log the email but don't send
	if !m.Config.Mail.Enabled {
		return fmt.Errorf("mail service is disabled: would have sent email to %s with subject: %s", email.To, email.Subject)
	}

	msg := mail.NewMessage()
	msg.SetHeader("From", fmt.Sprintf("%s <%s>", m.Config.Mail.FromName, m.Config.Mail.FromEmail))
	msg.SetHeader("To", email.To)
	msg.SetHeader("Subject", email.Subject)

	if email.ReplyTo != "" {
		msg.SetHeader("Reply-To", email.ReplyTo)
	}

	// Set body based on content type
	if email.IsHTML {
		msg.SetBody("text/html", email.Body)
	} else {
		msg.SetBody("text/plain", email.Body)
	}

	// Add attachments if any
	for _, attachment := range email.Attachments {
		msg.Attach(attachment)
	}

	// Send the email
	return m.dialer.DialAndSend(msg)
}

// SendVerificationEmail sends an email verification link
func (m *Mailer) SendVerificationEmail(to, username, token string) error {
	// Build the verification URL
	baseURL := m.Config.Auth.VerificationRedirectURL
	verificationURL := fmt.Sprintf("%s?token=%s", baseURL, token)

	// Load the email template
	templatePath := filepath.Join(m.Config.Mail.TemplatesPath, "verification.html")
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		// Fallback to a basic template if the file doesn't exist
		templateContent = []byte(`
			<h1>Verify Your Email</h1>
			<p>Hello {{.Username}},</p>
			<p>Thank you for registering with our service. Please click the link below to verify your email address:</p>
			<p><a href="{{.VerificationURL}}">Verify Email</a></p>
			<p>If you did not register for this service, please ignore this email.</p>
			<p>This link will expire in {{.ExpiryHours}} hours.</p>
		`)
	}

	// Parse and execute the template
	tmpl, err := template.New("verification").Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	data := struct {
		Username        string
		VerificationURL string
		ExpiryHours     int
		CurrentYear     int
	}{
		Username:        username,
		VerificationURL: verificationURL,
		ExpiryHours:     int(m.Config.Auth.VerificationTokenExpiry.Hours()),
		CurrentYear:     time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Create and send the email
	email := Email{
		To:      to,
		Subject: "Please Verify Your Email Address",
		Body:    body.String(),
		IsHTML:  true,
	}

	return m.Send(email)
}

// SendPasswordResetEmail sends a password reset link
func (m *Mailer) SendPasswordResetEmail(to, username, token string) error {
	// Build the reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", m.Config.Server.Host, token)

	// Load the email template
	templatePath := filepath.Join(m.Config.Mail.TemplatesPath, "password-reset.html")
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		// Fallback to a basic template if the file doesn't exist
		templateContent = []byte(`
			<h1>Reset Your Password</h1>
			<p>Hello {{.Username}},</p>
			<p>We received a request to reset your password. Please click the link below to create a new password:</p>
			<p><a href="{{.ResetURL}}">Reset Password</a></p>
			<p>If you did not request a password reset, please ignore this email.</p>
			<p>This link will expire in {{.ExpiryHours}} hours.</p>
		`)
	}

	// Parse and execute the template
	tmpl, err := template.New("password-reset").Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	data := struct {
		Username    string
		ResetURL    string
		ExpiryHours int
		CurrentYear int
	}{
		Username:    username,
		ResetURL:    resetURL,
		ExpiryHours: 24, // Assuming 24 hours for password reset
		CurrentYear: time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Create and send the email
	email := Email{
		To:      to,
		Subject: "Reset Your Password",
		Body:    body.String(),
		IsHTML:  true,
	}

	return m.Send(email)
}
