package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type GetSessionTokenAPIClient interface {
	GetSessionToken(ctx context.Context, param *sts.GetSessionTokenInput, optFns ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error)
}

type SessionTokenProvider struct {
	BaseCredsProvider aws.CredentialsProvider
	OTPSource         OTPSource
	StsClient         GetSessionTokenAPIClient
	MfaSerial         string
	Duration          time.Duration
}

func (p *SessionTokenProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	if _, err := p.BaseCredsProvider.Retrieve(ctx); err != nil {
		return nil, err
	}

	otp, err := p.OTPSource.OTP(ctx)
	if err != nil {
		return nil, err
	}

	out, err := p.StsClient.GetSessionToken(ctx, &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(int32(p.Duration.Seconds())),
		SerialNumber:    aws.String(p.MfaSerial),
		TokenCode:       aws.String(otp),
	})
	if err != nil {
		return nil, err
	}
	if out == nil || out.Credentials == nil {
		return nil, errors.New("sts credentials were empty")
	}

	return out.Credentials, nil
}

func (p *SessionTokenProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.RetrieveStsCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(creds.Expiration),
	}, nil
}

type StsSessionProvider interface {
	aws.CredentialsProvider
	RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error)
}

type CachedSessionProvider struct {
	SessionProvider StsSessionProvider
	CacheDir        string
	Profile         string
	ExpiryWindow    time.Duration
	OpAwsItem       OpAwsItem
	MfaSerial       string
	Now             func() time.Time
}

func (c *CachedSessionProvider) cachePath() string {
	return filepath.Join(c.CacheDir, "op-aws-credential-process", c.Profile+".json")
}

func (c *CachedSessionProvider) now() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

func (c *CachedSessionProvider) isValidEntry(entry cachedEntry) bool {
	if entry.Credentials == nil || entry.Credentials.Expiration == nil {
		return false
	}
	if entry.Vault != c.OpAwsItem.Vault {
		return false
	}
	if entry.Item != c.OpAwsItem.Item {
		return false
	}
	if entry.MfaSerial != c.MfaSerial {
		return false
	}
	if entry.AccessKeyIDField != c.OpAwsItem.AccessKeyIDField {
		return false
	}
	if entry.SecretAccessKeyField != c.OpAwsItem.SecretAccessKeyField {
		return false
	}

	return c.now().Add(c.ExpiryWindow).Before(*entry.Credentials.Expiration)
}

func (c *CachedSessionProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	data, err := os.ReadFile(c.cachePath())
	if err == nil {
		var cached cachedEntry
		if err := json.Unmarshal(data, &cached); err == nil && c.isValidEntry(cached) {
			return cached.Credentials, nil
		}
	}

	creds, err := c.SessionProvider.RetrieveStsCredentials(ctx)
	if err != nil {
		return nil, err
	}

	entry := cachedEntry{
		Credentials:          creds,
		Vault:                c.OpAwsItem.Vault,
		Item:                 c.OpAwsItem.Item,
		MfaSerial:            c.MfaSerial,
		AccessKeyIDField:     c.OpAwsItem.AccessKeyIDField,
		SecretAccessKeyField: c.OpAwsItem.SecretAccessKeyField,
	}
	_ = c.writeCache(entry)

	return creds, nil
}

func (c *CachedSessionProvider) writeCache(entry cachedEntry) error {
	if err := os.MkdirAll(filepath.Dir(c.cachePath()), 0700); err != nil {
		return err
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if err := os.WriteFile(c.cachePath(), data, 0600); err != nil {
		return err
	}

	return nil
}

func (c *CachedSessionProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := c.RetrieveStsCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(creds.Expiration),
	}, nil
}

type cachedEntry struct {
	Credentials          *ststypes.Credentials `json:"credentials"`
	Vault                string                `json:"vault"`
	Item                 string                `json:"item"`
	MfaSerial            string                `json:"mfa_serial"`
	AccessKeyIDField     string                `json:"access_key_id_field"`
	SecretAccessKeyField string                `json:"secret_access_key_field"`
}
