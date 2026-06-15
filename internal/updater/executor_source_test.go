package updater

import (
	"context"
	"errors"
	"testing"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
	"google.golang.org/grpc"
)

// fakeClient embeds the generated interface so it satisfies all methods; we
// override only the one CheckViaExecutor uses.
type fakeClient struct {
	executorV1.ExecutorClientServiceClient
	resp *executorV1.GetLatestClientReleaseResponse
	err  error
}

func (f *fakeClient) GetLatestClientRelease(_ context.Context, _ *executorV1.GetLatestClientReleaseRequest, _ ...grpc.CallOption) (*executorV1.GetLatestClientReleaseResponse, error) {
	return f.resp, f.err
}

func TestCheckViaExecutor_NotAvailable(t *testing.T) {
	c := &fakeClient{resp: &executorV1.GetLatestClientReleaseResponse{Available: false}}
	if _, err := CheckViaExecutor(context.Background(), c, "1.0.0"); !errors.Is(err, ErrReleaseNotCached) {
		t.Fatalf("want ErrReleaseNotCached, got %v", err)
	}
}

func TestCheckViaExecutor_MissingBinaryName(t *testing.T) {
	// available=true but no binary name => treat as not cached.
	c := &fakeClient{resp: &executorV1.GetLatestClientReleaseResponse{Available: true, Version: "1.2.0"}}
	if _, err := CheckViaExecutor(context.Background(), c, "1.0.0"); !errors.Is(err, ErrReleaseNotCached) {
		t.Fatalf("want ErrReleaseNotCached, got %v", err)
	}
}

func TestCheckViaExecutor_UpdateAvailable(t *testing.T) {
	c := &fakeClient{resp: &executorV1.GetLatestClientReleaseResponse{
		Available:  true,
		Version:    "1.2.0",
		BinaryName: "tangra-client-linux-amd64",
		Sha256:     "deadbeef",
		ReleaseUrl: "https://example/releases/1.2.0",
	}}
	res, err := CheckViaExecutor(context.Background(), c, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpdateAvail {
		t.Error("expected update available")
	}
	if res.LatestVersion != "1.2.0" {
		t.Errorf("LatestVersion = %q", res.LatestVersion)
	}
	if res.BinaryName != "tangra-client-linux-amd64" {
		t.Errorf("BinaryName = %q", res.BinaryName)
	}
	if res.ExpectedSHA256 != "deadbeef" {
		t.Errorf("ExpectedSHA256 = %q", res.ExpectedSHA256)
	}
}

func TestCheckViaExecutor_UpToDate(t *testing.T) {
	c := &fakeClient{resp: &executorV1.GetLatestClientReleaseResponse{
		Available:  true,
		Version:    "1.0.0",
		BinaryName: "tangra-client-linux-amd64",
	}}
	res, err := CheckViaExecutor(context.Background(), c, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.UpdateAvail {
		t.Error("expected no update when versions match")
	}
}
