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
	msg.SetHeader("Subject", "Email Verification")

	htmlBody := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #f9f9f9;
					margin: 0;
					padding: 0;
				}
				.container {
					max-width: 600px;
					margin: 20px auto;
					background: #ffffff;
					padding: 20px;
					border-radius: 8px;
					box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
				}
				.button {
					display: inline-block;
					padding: 10px 20px;
					color: #ffffff;
					background-color: #28a745;
					text-decoration: none;
					border-radius: 5px;
					font-size: 16px;
					font-weight: bold;
				}
				.button:hover {
					background-color: #218838;
				}
				.footer {
					margin-top: 20px;
					font-size: 12px;
					color: #666666;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h2>Email Verification</h2>
				<p>Hello,</p>
				<p>Thank you for registering! Please click the button below to verify your email address:</p>
				<a href="%s" class="button">Verify Email</a>
				<p>If you didn’t create an account, please ignore this email.</p>
				<p class="footer">This email was sent by InstaClone.</p>
			</div>
		</body>
		</html>
	`, url)

	msg.SetBody("text/html", htmlBody)

	return gomail.NewDialer(m.smtpHost, m.smtpPort, m.email, m.pass).DialAndSend(msg)
}

func (m *Mail) SendPasswordReset(to string, url string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.email)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", "Password Reset")

	htmlBody := fmt.Sprintf(`
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				body {
					font-family: Arial, sans-serif;
					background-color: #f9f9f9;
					margin: 0;
					padding: 0;
				}
				.container {
					max-width: 600px;
					margin: 20px auto;
					background: #ffffff;
					padding: 20px;
					border-radius: 8px;
					box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
				}
				.button {
					display: inline-block;
					padding: 10px 20px;
					color: #ffffff;
					background-color: #007BFF;
					text-decoration: none;
					border-radius: 5px;
					font-size: 16px;
					font-weight: bold;
				}
				.button:hover {
					background-color: #0056b3;
				}
				.footer {
					margin-top: 20px;
					font-size: 12px;
					color: #666666;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h2>Password Reset Request</h2>
				<p>Hello,</p>
				<p>You recently requested to reset your password. Click the button below to reset it:</p>
				<a href="%s" class="button">Reset Password</a>
				<p>If you didn’t request this, please ignore this email.</p>
				<p class="footer">This email was sent by InstaClone.</p>
			</div>
		</body>
		</html>
	`, url)
	msg.SetBody("text/html", htmlBody)

	return gomail.NewDialer(m.smtpHost, m.smtpPort, m.email, m.pass).DialAndSend(msg)
}
