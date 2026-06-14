package ipam

import (
	"testing"

	"github.com/go-tangra/go-tangra-client/internal/machine"
	"github.com/go-tangra/go-tangra-client/internal/storage"
)

func TestHasChanges_HostedVMs(t *testing.T) {
	base := &storage.HostInfoSnapshot{Hostname: "hela", HostedVMs: []string{"101:aa:bb:cc:dd:ee:01"}}

	cases := []struct {
		name string
		cur  *storage.HostInfoSnapshot
		want bool
	}{
		{"same", &storage.HostInfoSnapshot{Hostname: "hela", HostedVMs: []string{"101:aa:bb:cc:dd:ee:01"}}, false},
		{"reordered same", &storage.HostInfoSnapshot{Hostname: "hela", HostedVMs: []string{"101:aa:bb:cc:dd:ee:01"}}, false},
		{"guest added", &storage.HostInfoSnapshot{Hostname: "hela", HostedVMs: []string{"101:aa:bb:cc:dd:ee:01", "102:aa:bb:cc:dd:ee:02"}}, true},
		{"guest removed", &storage.HostInfoSnapshot{Hostname: "hela"}, true},
		{"mac changed", &storage.HostInfoSnapshot{Hostname: "hela", HostedVMs: []string{"101:aa:bb:cc:dd:ee:ff"}}, true},
	}
	for _, c := range cases {
		if got := HasChanges(base, c.cur); got != c.want {
			t.Errorf("%s: HasChanges = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSnapshotFromHostInfo_HostedVMs(t *testing.T) {
	info := &machine.HostInfo{
		Hostname: "hela",
		HostedVMs: []machine.HostedVM{
			{VMID: "101", MACs: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}},
			{VMID: "200", MACs: []string{"bc:24:11:aa:bb:cc"}},
		},
	}
	snap := SnapshotFromHostInfo(info)
	want := map[string]bool{
		"101:aa:bb:cc:dd:ee:01": true,
		"101:aa:bb:cc:dd:ee:02": true,
		"200:bc:24:11:aa:bb:cc": true,
	}
	if len(snap.HostedVMs) != len(want) {
		t.Fatalf("got %v, want %d entries", snap.HostedVMs, len(want))
	}
	for _, e := range snap.HostedVMs {
		if !want[e] {
			t.Errorf("unexpected entry %q", e)
		}
	}
}
