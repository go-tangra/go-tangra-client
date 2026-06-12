package ipam

import (
	"context"
	"errors"
	"testing"

	"github.com/go-tangra/go-tangra-client/internal/machine"
	"google.golang.org/grpc"

	ipampb "github.com/go-tangra/go-tangra-ipam/gen/go/ipam/service/v1"
)

// fakeDeviceClient implements ipampb.DeviceServiceClient. Embedding the
// interface satisfies the unused methods; only the ones exercised by
// createOrAdoptDevice are overridden.
type fakeDeviceClient struct {
	ipampb.DeviceServiceClient

	createResp *ipampb.CreateDeviceResponse
	createErr  error

	listItems []*ipampb.Device

	updateCalls   int
	updatedID     string
	lastListQuery string
}

func (f *fakeDeviceClient) CreateDevice(_ context.Context, _ *ipampb.CreateDeviceRequest, _ ...grpc.CallOption) (*ipampb.CreateDeviceResponse, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResp, nil
}

func (f *fakeDeviceClient) ListDevices(_ context.Context, in *ipampb.ListDevicesRequest, _ ...grpc.CallOption) (*ipampb.ListDevicesResponse, error) {
	f.lastListQuery = in.GetQuery()
	return &ipampb.ListDevicesResponse{Items: f.listItems}, nil
}

func (f *fakeDeviceClient) UpdateDevice(_ context.Context, in *ipampb.UpdateDeviceRequest, _ ...grpc.CallOption) (*ipampb.UpdateDeviceResponse, error) {
	f.updateCalls++
	f.updatedID = in.GetId()
	return &ipampb.UpdateDeviceResponse{}, nil
}

func strp(s string) *string { return &s }

func TestCreateOrAdoptDevice(t *testing.T) {
	const host = "zax-9.infra.verax.net"
	info := &machine.HostInfo{Hostname: host}

	t.Run("creates when no conflict", func(t *testing.T) {
		fake := &fakeDeviceClient{
			createResp: &ipampb.CreateDeviceResponse{
				Device: &ipampb.Device{Id: strp("new-id")},
			},
		}
		clients := &IPAMClients{Device: fake}

		id, err := createOrAdoptDevice(context.Background(), clients, info, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "new-id" {
			t.Fatalf("got id %q, want %q", id, "new-id")
		}
		if fake.updateCalls != 0 {
			t.Fatalf("UpdateDevice should not be called on a clean create, got %d", fake.updateCalls)
		}
	})

	t.Run("adopts existing device by exact name on conflict", func(t *testing.T) {
		fake := &fakeDeviceClient{
			createErr: ipampb.ErrorDeviceAlreadyExists("device '%s' already exists", host),
			listItems: []*ipampb.Device{
				// A substring match that must be ignored.
				{Id: strp("wrong-id"), Name: strp("zax-90.infra.verax.net")},
				{Id: strp("existing-id"), Name: strp(host)},
			},
		}
		clients := &IPAMClients{Device: fake}

		id, err := createOrAdoptDevice(context.Background(), clients, info, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "existing-id" {
			t.Fatalf("got id %q, want %q", id, "existing-id")
		}
		if fake.lastListQuery != host {
			t.Fatalf("list query = %q, want %q", fake.lastListQuery, host)
		}
		if fake.updateCalls != 1 || fake.updatedID != "existing-id" {
			t.Fatalf("expected UpdateDevice on existing-id once, got calls=%d id=%q", fake.updateCalls, fake.updatedID)
		}
	})

	t.Run("errors when conflict but no exact match found", func(t *testing.T) {
		fake := &fakeDeviceClient{
			createErr: ipampb.ErrorDeviceAlreadyExists("device '%s' already exists", host),
			listItems: []*ipampb.Device{
				{Id: strp("wrong-id"), Name: strp("zax-90.infra.verax.net")},
			},
		}
		clients := &IPAMClients{Device: fake}

		if _, err := createOrAdoptDevice(context.Background(), clients, info, 0); err == nil {
			t.Fatal("expected error when no exact-name match is found, got nil")
		}
		if fake.updateCalls != 0 {
			t.Fatalf("UpdateDevice should not be called when adoption fails, got %d", fake.updateCalls)
		}
	})

	t.Run("propagates non-conflict create errors without lookup", func(t *testing.T) {
		fake := &fakeDeviceClient{createErr: errors.New("connection refused")}
		clients := &IPAMClients{Device: fake}

		if _, err := createOrAdoptDevice(context.Background(), clients, info, 0); err == nil {
			t.Fatal("expected create error to propagate, got nil")
		}
		if fake.lastListQuery != "" {
			t.Fatal("ListDevices should not be called for non-conflict errors")
		}
	})
}
