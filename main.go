package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kong"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

var version = "dev"

var cli struct {
	Profile                string           `default:"default" help:"AWS config profile name."`
	Duration               time.Duration    `default:"12h" help:"STS session duration."`
	OpVault                string           `required:"" help:"1Password vault name."`
	OpItem                 string           `required:"" help:"1Password item name."`
	OpAccessKeyIDField     string           `default:"username" help:"1Password field name for access key ID." name:"op-access-key-id-field"`
	OpSecretAccessKeyField string           `default:"credential" help:"1Password field name for secret access key." name:"op-secret-access-key-field"`
	OpCLIPath              string           `default:"op" help:"Path to 1Password CLI." name:"op-cli-path"`
	Version                kong.VersionFlag `help:"Show version."`
}

type OpAwsItem struct {
	Vault                string
	Item                 string
	AccessKeyIDField     string
	SecretAccessKeyField string
}

func main() {
	kong.Parse(&cli,
		kong.Name("op-aws-credential-helper"),
		kong.Description("AWS credential_process helper that retrieves credentials from 1Password with MFA session caching"),
		kong.Vars{"version": version},
	)

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	cfg, err := config.LoadSharedConfigProfile(ctx, cli.Profile)
	if err != nil {
		return err
	}

	opCLISource := &opCLICredentialSource{
		cliPath: cli.OpCLIPath,
		OpAwsItem: OpAwsItem{
			Vault:                cli.OpVault,
			Item:                 cli.OpItem,
			AccessKeyIDField:     cli.OpAccessKeyIDField,
			SecretAccessKeyField: cli.OpSecretAccessKeyField,
		},
	}

	cachedCreds := aws.NewCredentialsCache(opCLISource)

	stsClient := sts.New(sts.Options{
		Region:      cfg.Region,
		Credentials: cachedCreds,
	})

	dir, err := cacheDir()
	if err != nil {
		return err
	}

	source := &CachedSessionProvider{
		SessionProvider: &SessionTokenProvider{
			BaseCredsProvider: cachedCreds,
			OTPSource:         &ttyOTPSource{},
			StsClient:         stsClient,
			MfaSerial:         cfg.MFASerial,
			Duration:          cli.Duration,
		},
		CacheDir:     dir,
		Profile:      cli.Profile,
		ExpiryWindow: expiryWindow,
		OpAwsItem:    opCLISource.OpAwsItem,
		MfaSerial:    cfg.MFASerial,
	}

	creds, err := source.RetrieveStsCredentials(ctx)
	if err != nil {
		return err
	}

	return json.NewEncoder(os.Stdout).Encode(toCredentialProcessResponse(creds))
}

const expiryWindow = 5 * time.Minute

func toCredentialProcessResponse(creds *ststypes.Credentials) processcreds.CredentialProcessResponse {
	return processcreds.CredentialProcessResponse{
		Version:         1,
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		Expiration:      creds.Expiration,
	}
}

func cacheDir() (string, error) {
	dir := os.Getenv("XDG_CACHE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".cache")
	}
	return dir, nil
}
