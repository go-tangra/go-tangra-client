package updater

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

// ErrReleaseNotCached is returned by CheckViaExecutor when the executor has no
// cached binary for the running platform. Callers should fall back to GitHub.
var ErrReleaseNotCached = errors.New("executor has no cached release for this platform")

// CheckViaExecutor asks the executor for the latest cached client release for
// the running platform and compares it against the current version. It returns
// ErrReleaseNotCached when the executor has nothing usable cached yet.
func CheckViaExecutor(ctx context.Context, client executorV1.ExecutorClientServiceClient, currentVersion string) (*UpdateResult, error) {
	resp, err := client.GetLatestClientRelease(ctx, &executorV1.GetLatestClientReleaseRequest{
		Os:   runtime.GOOS,
		Arch: runtime.GOARCH,
	})
	if err != nil {
		return nil, fmt.Errorf("querying executor for latest release: %w", err)
	}

	if !resp.GetAvailable() || resp.GetBinaryName() == "" {
		return nil, ErrReleaseNotCached
	}

	return &UpdateResult{
		CurrentVersion: currentVersion,
		LatestVersion:  resp.GetVersion(),
		UpdateAvail:    compareVersions(currentVersion, resp.GetVersion()) < 0,
		BinaryName:     resp.GetBinaryName(),
		ExpectedSHA256: resp.GetSha256(),
		ReleaseURL:     resp.GetReleaseUrl(),
	}, nil
}

// DownloadAndApplyViaExecutor streams the cached binary from the executor,
// verifies its checksum, and applies the update.
func DownloadAndApplyViaExecutor(ctx context.Context, client executorV1.ExecutorClientServiceClient, result *UpdateResult) error {
	var expectedChecksum []byte
	if result.ExpectedSHA256 != "" {
		sum, err := hex.DecodeString(result.ExpectedSHA256)
		if err != nil {
			return fmt.Errorf("invalid checksum from executor: %w", err)
		}
		expectedChecksum = sum
	}

	fmt.Printf("Downloading %s from executor...\n", result.BinaryName)
	stream, err := client.DownloadClientBinary(ctx, &executorV1.DownloadClientBinaryRequest{
		BinaryName: result.BinaryName,
		Version:    result.LatestVersion,
	})
	if err != nil {
		return fmt.Errorf("starting binary download from executor: %w", err)
	}

	var buf bytes.Buffer
	for {
		chunk, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return fmt.Errorf("receiving binary from executor: %w", recvErr)
		}
		buf.Write(chunk.GetData())
	}

	if buf.Len() == 0 {
		return fmt.Errorf("executor returned an empty binary")
	}

	return applyBinary(bytes.NewReader(buf.Bytes()), expectedChecksum, result.LatestVersion)
}
