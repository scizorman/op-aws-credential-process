package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type fakeOTPSource struct {
	otp    string
	err    error
	called int
}

func (f *fakeOTPSource) OTP(ctx context.Context) (string, error) {
	f.called++
	return f.otp, f.err
}

type fakeCredsProvider struct {
	creds  aws.Credentials
	err    error
	called int
}

func (f *fakeCredsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	f.called++
	return f.creds, f.err
}

type fakeSTSClient struct {
	output    *sts.GetSessionTokenOutput
	err       error
	lastInput *sts.GetSessionTokenInput
}

func (f *fakeSTSClient) GetSessionToken(ctx context.Context, params *sts.GetSessionTokenInput, optFns ...func(*sts.Options)) (*sts.GetSessionTokenOutput, error) {
	f.lastInput = params
	return f.output, f.err
}

type fakeStsSessionProvider struct {
	creds  *ststypes.Credentials
	err    error
	called int
}

func (f *fakeStsSessionProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	f.called++
	if f.err != nil {
		return nil, f.err
	}
	return f.creds, nil
}

func (f *fakeStsSessionProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := f.RetrieveStsCredentials(ctx)
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

func newStsCreds(accessKey, secret, token string, expiration time.Time) *ststypes.Credentials {
	return &ststypes.Credentials{
		AccessKeyId:     aws.String(accessKey),
		SecretAccessKey: aws.String(secret),
		SessionToken:    aws.String(token),
		Expiration:      aws.Time(expiration),
	}
}

func defaultOpAwsItem() OpAwsItem {
	return OpAwsItem{
		Vault:                "vault-a",
		Item:                 "item-a",
		AccessKeyIDField:     "username",
		SecretAccessKeyField: "credential",
	}
}

func readCachedEntry(t *testing.T, path string) cachedEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}
	var entry cachedEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to unmarshal cache entry: %v", err)
	}
	return entry
}

func TestSessionTokenProvider_Retrieve(t *testing.T) {
	expiration := time.Now().Add(1 * time.Hour)
	otpSource := &fakeOTPSource{otp: "123456"}
	stsClient := &fakeSTSClient{
		output: &sts.GetSessionTokenOutput{Credentials: newStsCreds("AKIA", "SECRET", "TOKEN", expiration)},
	}

	provider := &SessionTokenProvider{
		BaseCredsProvider: &fakeCredsProvider{},
		OTPSource:         otpSource,
		StsClient:         stsClient,
		MfaSerial:         "arn:aws:iam::123456789012:mfa/user",
		Duration:          12 * time.Hour,
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "AKIA" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "AKIA")
	}
	if got.SecretAccessKey != "SECRET" {
		t.Errorf("SecretAccessKey = %q, want %q", got.SecretAccessKey, "SECRET")
	}
	if got.SessionToken != "TOKEN" {
		t.Errorf("SessionToken = %q, want %q", got.SessionToken, "TOKEN")
	}
	if !got.CanExpire {
		t.Errorf("CanExpire = %v, want true", got.CanExpire)
	}
	if !got.Expires.Equal(expiration) {
		t.Errorf("Expires = %v, want %v", got.Expires, expiration)
	}
	if stsClient.lastInput == nil {
		t.Fatal("GetSessionToken was not called")
	}
	if got := aws.ToInt32(stsClient.lastInput.DurationSeconds); got != int32((12 * time.Hour).Seconds()) {
		t.Errorf("DurationSeconds = %d, want %d", got, int32((12 * time.Hour).Seconds()))
	}
	if got := aws.ToString(stsClient.lastInput.SerialNumber); got != "arn:aws:iam::123456789012:mfa/user" {
		t.Errorf("SerialNumber = %q, want %q", got, "arn:aws:iam::123456789012:mfa/user")
	}
}

func TestSessionTokenProvider_OTPError(t *testing.T) {
	provider := &SessionTokenProvider{
		BaseCredsProvider: &fakeCredsProvider{},
		OTPSource:         &fakeOTPSource{err: errors.New("failed to get OTP")},
		StsClient:         &fakeSTSClient{},
		MfaSerial:         "arn:aws:iam::123456789012:mfa/user",
		Duration:          12 * time.Hour,
	}

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "failed to get OTP" {
		t.Errorf("error = %q, want %q", err.Error(), "failed to get OTP")
	}
}

func TestSessionTokenProvider_STSError(t *testing.T) {
	provider := &SessionTokenProvider{
		BaseCredsProvider: &fakeCredsProvider{},
		OTPSource:         &fakeOTPSource{otp: "123456"},
		StsClient:         &fakeSTSClient{err: errors.New("STS call failed")},
		MfaSerial:         "arn:aws:iam::123456789012:mfa/user",
		Duration:          12 * time.Hour,
	}

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "STS call failed" {
		t.Errorf("error = %q, want %q", err.Error(), "STS call failed")
	}
}

func TestSessionTokenProvider_RetrieveStsCredentials(t *testing.T) {
	expiration := time.Now().Add(1 * time.Hour)
	provider := &SessionTokenProvider{
		BaseCredsProvider: &fakeCredsProvider{},
		OTPSource:         &fakeOTPSource{otp: "123456"},
		StsClient: &fakeSTSClient{
			output: &sts.GetSessionTokenOutput{Credentials: newStsCreds("AKIA", "SECRET", "TOKEN", expiration)},
		},
		MfaSerial: "arn:aws:iam::123456789012:mfa/user",
		Duration:  12 * time.Hour,
	}

	creds, err := provider.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := aws.ToString(creds.AccessKeyId); got != "AKIA" {
		t.Errorf("AccessKeyId = %q, want %q", got, "AKIA")
	}
}

func TestSessionTokenProvider_BaseCredsError(t *testing.T) {
	baseCreds := &fakeCredsProvider{err: errors.New("base creds error")}
	otpSource := &fakeOTPSource{otp: "123456"}
	provider := &SessionTokenProvider{
		BaseCredsProvider: baseCreds,
		OTPSource:         otpSource,
		StsClient:         &fakeSTSClient{},
		MfaSerial:         "arn:aws:iam::123456789012:mfa/user",
		Duration:          12 * time.Hour,
	}

	_, err := provider.RetrieveStsCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "base creds error" {
		t.Errorf("error = %q, want %q", err.Error(), "base creds error")
	}
	if baseCreds.called != 1 {
		t.Errorf("baseCreds.called = %d, want 1", baseCreds.called)
	}
	if otpSource.called != 0 {
		t.Errorf("otpSource.called = %d, want 0", otpSource.called)
	}
}

func TestCachedSessionProvider_NoCacheFile(t *testing.T) {
	cacheDir := t.TempDir()
	exp := time.Now().Add(1 * time.Hour)
	inner := &fakeStsSessionProvider{creds: newStsCreds("INNER_KEY", "INNER_SECRET", "INNER_TOKEN", exp)}

	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "INNER_KEY" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "INNER_KEY")
	}
	if inner.called != 1 {
		t.Errorf("inner.called = %d, want 1", inner.called)
	}
	if _, err := os.Stat(provider.cachePath()); err != nil {
		t.Fatalf("cache file was not created: %v", err)
	}
	entry := readCachedEntry(t, provider.cachePath())
	if entry.Vault != provider.OpAwsItem.Vault {
		t.Errorf("entry.Vault = %q, want %q", entry.Vault, provider.OpAwsItem.Vault)
	}
}

func TestCachedSessionProvider_ValidCache(t *testing.T) {
	cacheDir := t.TempDir()
	exp := time.Now().Add(1 * time.Hour)
	inner := &fakeStsSessionProvider{creds: newStsCreds("INNER_KEY", "INNER_SECRET", "INNER_TOKEN", exp)}

	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	cached := cachedEntry{
		Credentials:          newStsCreds("CACHED_KEY", "CACHED_SECRET", "CACHED_TOKEN", exp),
		Vault:                provider.OpAwsItem.Vault,
		Item:                 provider.OpAwsItem.Item,
		MfaSerial:            provider.MfaSerial,
		AccessKeyIDField:     provider.OpAwsItem.AccessKeyIDField,
		SecretAccessKeyField: provider.OpAwsItem.SecretAccessKeyField,
	}
	if err := provider.writeCache(cached); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "CACHED_KEY" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "CACHED_KEY")
	}
	if inner.called != 0 {
		t.Errorf("inner.called = %d, want 0", inner.called)
	}
}

func TestCachedSessionProvider_ParameterMismatchCausesCacheMiss(t *testing.T) {
	keys := []string{"vault", "item", "mfa", "accessKeyField", "secretKeyField"}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			cacheDir := t.TempDir()
			exp := time.Now().Add(1 * time.Hour)
			inner := &fakeStsSessionProvider{creds: newStsCreds("FRESH_KEY", "FRESH_SECRET", "FRESH_TOKEN", exp)}

			provider := &CachedSessionProvider{
				SessionProvider: inner,
				CacheDir:        cacheDir,
				Profile:         "test-profile",
				ExpiryWindow:    5 * time.Minute,
				OpAwsItem:       defaultOpAwsItem(),
				MfaSerial:       "mfa-serial",
			}

			cached := cachedEntry{
				Credentials:          newStsCreds("CACHED_KEY", "CACHED_SECRET", "CACHED_TOKEN", exp),
				Vault:                provider.OpAwsItem.Vault,
				Item:                 provider.OpAwsItem.Item,
				MfaSerial:            provider.MfaSerial,
				AccessKeyIDField:     provider.OpAwsItem.AccessKeyIDField,
				SecretAccessKeyField: provider.OpAwsItem.SecretAccessKeyField,
			}

			switch key {
			case "vault":
				cached.Vault = "different-vault"
			case "item":
				cached.Item = "different-item"
			case "mfa":
				cached.MfaSerial = "different-mfa"
			case "accessKeyField":
				cached.AccessKeyIDField = "different-access-key-field"
			case "secretKeyField":
				cached.SecretAccessKeyField = "different-secret-key-field"
			}

			if err := provider.writeCache(cached); err != nil {
				t.Fatalf("failed to write cache: %v", err)
			}

			got, err := provider.Retrieve(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.AccessKeyID != "FRESH_KEY" {
				t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "FRESH_KEY")
			}
			if inner.called != 1 {
				t.Errorf("inner.called = %d, want 1", inner.called)
			}
		})
	}
}

func TestCachedSessionProvider_ExpiredCache(t *testing.T) {
	cacheDir := t.TempDir()
	inner := &fakeStsSessionProvider{creds: newStsCreds("FRESH_KEY", "FRESH_SECRET", "FRESH_TOKEN", time.Now().Add(1*time.Hour))}
	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	expired := cachedEntry{
		Credentials:          newStsCreds("OLD_KEY", "OLD_SECRET", "OLD_TOKEN", time.Now().Add(2*time.Minute)),
		Vault:                provider.OpAwsItem.Vault,
		Item:                 provider.OpAwsItem.Item,
		MfaSerial:            provider.MfaSerial,
		AccessKeyIDField:     provider.OpAwsItem.AccessKeyIDField,
		SecretAccessKeyField: provider.OpAwsItem.SecretAccessKeyField,
	}
	if err := provider.writeCache(expired); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "FRESH_KEY" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "FRESH_KEY")
	}
	if inner.called != 1 {
		t.Errorf("inner.called = %d, want 1", inner.called)
	}
}

func TestCachedSessionProvider_CorruptedCache(t *testing.T) {
	cacheDir := t.TempDir()
	exp := time.Now().Add(1 * time.Hour)
	inner := &fakeStsSessionProvider{creds: newStsCreds("FRESH_KEY", "FRESH_SECRET", "FRESH_TOKEN", exp)}
	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	if err := os.MkdirAll(filepath.Dir(provider.cachePath()), 0700); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	if err := os.WriteFile(provider.cachePath(), []byte("invalid json"), 0600); err != nil {
		t.Fatalf("failed to write corrupted cache: %v", err)
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "FRESH_KEY" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "FRESH_KEY")
	}
	if inner.called != 1 {
		t.Errorf("inner.called = %d, want 1", inner.called)
	}
}

func TestCachedSessionProvider_InnerError(t *testing.T) {
	provider := &CachedSessionProvider{
		SessionProvider: &fakeStsSessionProvider{err: errors.New("inner error")},
		CacheDir:        t.TempDir(),
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "inner error" {
		t.Errorf("error = %q, want %q", err.Error(), "inner error")
	}
	if _, statErr := os.Stat(provider.cachePath()); !os.IsNotExist(statErr) {
		t.Fatalf("cache should not be written on error, statErr=%v", statErr)
	}
}

func TestCachedSessionProvider_CacheWriteFailureIsNonFatal(t *testing.T) {
	cacheDir := t.TempDir()
	blockingPath := filepath.Join(cacheDir, "op-aws-credential-helper")
	if err := os.WriteFile(blockingPath, []byte("not-a-directory"), 0600); err != nil {
		t.Fatalf("failed to create blocking file: %v", err)
	}

	inner := &fakeStsSessionProvider{creds: newStsCreds("FRESH_KEY", "FRESH_SECRET", "FRESH_TOKEN", time.Now().Add(1*time.Hour))}
	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	got, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.AccessKeyID != "FRESH_KEY" {
		t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "FRESH_KEY")
	}
	if inner.called != 1 {
		t.Errorf("inner.called = %d, want 1", inner.called)
	}
}

func TestCachedSessionProvider_CacheDirectoryCreated(t *testing.T) {
	cacheDir := t.TempDir()
	provider := &CachedSessionProvider{
		SessionProvider: &fakeStsSessionProvider{creds: newStsCreds("KEY", "SECRET", "TOKEN", time.Now().Add(1*time.Hour))},
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	if _, err := provider.Retrieve(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dir := filepath.Join(cacheDir, "op-aws-credential-helper")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("cache directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("cache path is not a directory")
	}
}

func TestCachedSessionProvider_CachePath(t *testing.T) {
	provider := &CachedSessionProvider{CacheDir: "/tmp/cache", Profile: "dev"}
	if got := provider.cachePath(); got != "/tmp/cache/op-aws-credential-helper/dev.json" {
		t.Errorf("cachePath = %q, want %q", got, "/tmp/cache/op-aws-credential-helper/dev.json")
	}
}

func TestCachedSessionProvider_RetrieveStsCredentialsCacheHit(t *testing.T) {
	cacheDir := t.TempDir()
	exp := time.Now().Add(1 * time.Hour)
	inner := &fakeStsSessionProvider{creds: newStsCreds("INNER_KEY", "INNER_SECRET", "INNER_TOKEN", exp)}
	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}
	if err := provider.writeCache(cachedEntry{
		Credentials:          newStsCreds("CACHED_KEY", "CACHED_SECRET", "CACHED_TOKEN", exp),
		Vault:                provider.OpAwsItem.Vault,
		Item:                 provider.OpAwsItem.Item,
		MfaSerial:            provider.MfaSerial,
		AccessKeyIDField:     provider.OpAwsItem.AccessKeyIDField,
		SecretAccessKeyField: provider.OpAwsItem.SecretAccessKeyField,
	}); err != nil {
		t.Fatalf("failed to write cache: %v", err)
	}

	creds, err := provider.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := aws.ToString(creds.AccessKeyId); got != "CACHED_KEY" {
		t.Errorf("AccessKeyId = %q, want %q", got, "CACHED_KEY")
	}
	if inner.called != 0 {
		t.Errorf("inner.called = %d, want 0", inner.called)
	}
}

func TestCachedSessionProvider_RetrieveStsCredentialsCacheMiss(t *testing.T) {
	cacheDir := t.TempDir()
	exp := time.Now().Add(1 * time.Hour)
	inner := &fakeStsSessionProvider{creds: newStsCreds("FRESH_KEY", "FRESH_SECRET", "FRESH_TOKEN", exp)}
	provider := &CachedSessionProvider{
		SessionProvider: inner,
		CacheDir:        cacheDir,
		Profile:         "test-profile",
		ExpiryWindow:    5 * time.Minute,
		OpAwsItem:       defaultOpAwsItem(),
		MfaSerial:       "mfa-serial",
	}

	creds, err := provider.RetrieveStsCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := aws.ToString(creds.AccessKeyId); got != "FRESH_KEY" {
		t.Errorf("AccessKeyId = %q, want %q", got, "FRESH_KEY")
	}
	if inner.called != 1 {
		t.Errorf("inner.called = %d, want 1", inner.called)
	}
}

func TestToCredentialProcessResponse(t *testing.T) {
	expiration := time.Now().Add(1 * time.Hour)
	resp := toCredentialProcessResponse(newStsCreds("AKIA", "SECRET", "TOKEN", expiration))

	if resp.Version != 1 {
		t.Errorf("Version = %d, want 1", resp.Version)
	}
	if resp.AccessKeyID != "AKIA" {
		t.Errorf("AccessKeyID = %q, want %q", resp.AccessKeyID, "AKIA")
	}
	if resp.SecretAccessKey != "SECRET" {
		t.Errorf("SecretAccessKey = %q, want %q", resp.SecretAccessKey, "SECRET")
	}
	if resp.SessionToken != "TOKEN" {
		t.Errorf("SessionToken = %q, want %q", resp.SessionToken, "TOKEN")
	}
	if resp.Expiration == nil || !resp.Expiration.Equal(expiration) {
		t.Errorf("Expiration = %v, want %v", resp.Expiration, expiration)
	}
}

var _ aws.CredentialsProvider = (*SessionTokenProvider)(nil)
var _ aws.CredentialsProvider = (*CachedSessionProvider)(nil)
var _ StsSessionProvider = (*SessionTokenProvider)(nil)
