package service

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

type (
	Mail struct {
		email    string
		pass     string
		smtpHost string
		smtpPort int
	}
	MailOpts struct {
		Email    string
		Password string
		SMTPHost string
		SMTPPort int
	}
)

func NewMail(opts MailOpts) *Mail {
	return &Mail{
		email:    opts.Email,
		pass:     opts.Password,
		smtpHost: opts.SMTPHost,
		smtpPort: opts.SMTPPort,
	}
}

func (m *Mail) SendEmailVerification(to string, url string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.email)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", "Email verification")
	msg.SetBody("text/html", fmt.Sprintf(`<a href="%s">Verify</a>`, url))

	return gomail.NewDialer(m.smtpHost, m.smtpPort, m.email, m.pass).DialAndSend(msg)
}

func (m *Mail) SendPasswordReset(to string, url string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.email)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", "Password reset")
	msg.SetBody("text/html", fmt.Sprintf(`<a href="%s">Reset</a>`, url))

	return gomail.NewDialer(m.smtpHost, m.smtpPort, m.email, m.pass).DialAndSend(msg)
}
