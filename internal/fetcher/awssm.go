package fetcher

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const awsSMScheme = "awssm://"

// secretGetter is the subset of the Secrets Manager client the fetcher uses.
type secretGetter interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// AWSSMFetcher retrieves secret strings from AWS Secrets Manager.
type AWSSMFetcher struct {
	client secretGetter
}

// NewAWSSMFetcher creates a Secrets Manager fetcher using the default AWS credential chain.
func NewAWSSMFetcher(ctx context.Context) (*AWSSMFetcher, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	// Secrets live in one region, which may differ from the env's own region.
	if region := os.Getenv("AWS_SM_REGION"); region != "" {
		cfg.Region = region
	}

	return &AWSSMFetcher{client: secretsmanager.NewFromConfig(cfg)}, nil
}

// Supports returns true for awssm:// URIs.
func (f *AWSSMFetcher) Supports(uri string) bool {
	return strings.HasPrefix(uri, awsSMScheme)
}

// Fetch returns the SecretString of the secret named in an awssm://<secret-name> URI.
func (f *AWSSMFetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	name := strings.TrimPrefix(uri, awsSMScheme)
	if name == "" {
		return nil, fmt.Errorf("invalid Secrets Manager URI: %s", uri)
	}

	out, err := f.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)})
	if err != nil {
		return nil, fmt.Errorf("fetching secret %q from AWS Secrets Manager: %w", name, err)
	}
	if out.SecretString == nil {
		return nil, fmt.Errorf("secret %q has no string value", name)
	}

	return []byte(*out.SecretString), nil
}
