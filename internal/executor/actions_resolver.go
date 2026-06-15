package executor

import (
	"context"
	"fmt"
	"testing/fstest"

	"github.com/go-tangra/go-tangra-actions/engine"
	"github.com/go-tangra/go-tangra-actions/workflow"

	executorV1 "github.com/go-tangra/go-tangra-executor/gen/go/executor/service/v1"
)

// executorResolver resolves a workflow's `uses:` action reference by fetching the
// action package (manifest + files) from the executor's action repository over
// the mTLS gRPC connection. It implements engine.Resolver.
type executorResolver struct {
	client executorV1.ExecutorClientServiceClient
}

func newExecutorResolver(client executorV1.ExecutorClientServiceClient) *executorResolver {
	return &executorResolver{client: client}
}

// Resolve fetches and parses the named action from the executor.
func (r *executorResolver) Resolve(ctx context.Context, ref string) (*engine.ResolvedAction, error) {
	resp, err := r.client.ResolveAction(ctx, &executorV1.ResolveActionRequest{Name: ref})
	if err != nil {
		return nil, fmt.Errorf("resolve action %q from executor: %w", ref, err)
	}

	def, err := workflow.ParseAction([]byte(resp.GetManifest()))
	if err != nil {
		return nil, fmt.Errorf("parse action %q manifest: %w", ref, err)
	}

	files := fstest.MapFS{}
	for _, f := range resp.GetFiles() {
		if f.GetPath() == "" {
			continue
		}
		files[f.GetPath()] = &fstest.MapFile{Data: []byte(f.GetContent())}
	}

	return &engine.ResolvedAction{Def: def, Files: files}, nil
}
