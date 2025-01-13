package service

type (
	Mail struct {
		email string
		pass  string
	}
	MailOpts struct {
		Email    string
		Password string
	}
)

func NewMail(opts MailOpts) *Mail {
	return &Mail{
		email: opts.Email,
		pass:  opts.Password,
	}
}

func (m *Mail) SendEmailVerification(to string, url string) error {
	return nil
}

func (m *Mail) SendPasswordReset(to string, url string) error {
	return nil
}
