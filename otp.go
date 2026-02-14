package main

import (
	"context"
	"fmt"
	"os"
)

type OTPSource interface {
	OTP(ctx context.Context) (string, error)
}

type ttyOTPSource struct{}

func (s *ttyOTPSource) OTP(ctx context.Context) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = tty.Close()
	}()

	if _, err := fmt.Fprint(tty, "Enter MFA code: "); err != nil {
		return "", err
	}
	var code string
	if _, err := fmt.Fscanln(tty, &code); err != nil {
		return "", err
	}
	return code, nil
}
