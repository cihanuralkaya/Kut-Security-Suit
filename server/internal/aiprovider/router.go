package aiprovider

import (
	"context"
	"errors"
	"fmt"
)

type ModelRouter struct {
	localProvider ModelProvider
	cloudProvider ModelProvider
	mockProvider  ModelProvider
}

func NewModelRouter(local, cloud, mock ModelProvider) *ModelRouter {
	return &ModelRouter{
		localProvider: local,
		cloudProvider: cloud,
		mockProvider:  mock,
	}
}

func (r *ModelRouter) RouteComplete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	if req.Sensitivity == Restricted {
		if r.localProvider == nil {
			return CompletionResponse{}, errors.New("restricted sensitivity requires local provider, but none is configured")
		}
		resp, err := r.localProvider.Complete(ctx, req)
		if err != nil {
			if r.mockProvider != nil {
				return r.mockProvider.Complete(ctx, req)
			}
			return CompletionResponse{}, fmt.Errorf("local provider failed: %w", err)
		}
		return resp, nil
	}

	if r.cloudProvider != nil {
		resp, err := r.cloudProvider.Complete(ctx, req)
		if err == nil {
			return resp, nil
		}
	}

	if r.localProvider != nil {
		resp, err := r.localProvider.Complete(ctx, req)
		if err == nil {
			return resp, nil
		}
	}

	if r.mockProvider != nil {
		return r.mockProvider.Complete(ctx, req)
	}

	return CompletionResponse{}, errors.New("all providers failed")
}
