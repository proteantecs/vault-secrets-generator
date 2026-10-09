package fetcher

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSM struct {
	out *secretsmanager.GetSecretValueOutput
	err error
	id  string
}

func (f *fakeSM) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.id = aws.ToString(in.SecretId)
	return f.out, f.err
}

func TestAWSSMFetcher_Supports(t *testing.T) {
	f := &AWSSMFetcher{}
	for uri, want := range map[string]bool{
		"awssm://vault/prod/shared": true,
		"s3://bucket/key":           false,
		"":                          false,
	} {
		if got := f.Supports(uri); got != want {
			t.Errorf("Supports(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestAWSSMFetcher_Fetch(t *testing.T) {
	fake := &fakeSM{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(`{"foo":"bar"}`)}}
	f := &AWSSMFetcher{client: fake}

	data, err := f.Fetch(context.Background(), "awssm://vault/prod/shared")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if string(data) != `{"foo":"bar"}` || fake.id != "vault/prod/shared" {
		t.Errorf("Fetch() = %q for id %q", data, fake.id)
	}
}

func TestAWSSMFetcher_FetchErrors(t *testing.T) {
	ctx := context.Background()

	if _, err := (&AWSSMFetcher{client: &fakeSM{err: errors.New("denied")}}).Fetch(ctx, "awssm://x"); err == nil {
		t.Error("expected error from client")
	}
	if _, err := (&AWSSMFetcher{client: &fakeSM{out: &secretsmanager.GetSecretValueOutput{}}}).Fetch(ctx, "awssm://x"); err == nil {
		t.Error("expected error for binary secret")
	}
	if _, err := (&AWSSMFetcher{}).Fetch(ctx, "awssm://"); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestNewAWSSMFetcher_RegionOverride(t *testing.T) {
	t.Setenv("AWS_REGION", "ap-northeast-1")
	t.Setenv("AWS_SM_REGION", "eu-west-1")

	f, err := NewAWSSMFetcher(context.Background())
	if err != nil {
		t.Fatalf("NewAWSSMFetcher() error = %v", err)
	}
	if got := f.client.(*secretsmanager.Client).Options().Region; got != "eu-west-1" {
		t.Errorf("region = %q, want eu-west-1", got)
	}
}
