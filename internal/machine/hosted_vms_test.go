package machine

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseGuestConfig_QemuMACsAndName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "101.conf")
	content := `name: web01
cores: 2
memory: 2048
net0: virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0,firewall=1
net1: e1000=AA:BB:CC:DD:EE:02,bridge=vmbr1
scsi0: local-lvm:vm-101-disk-0,size=32G
[snapshotA]
net0: virtio=DE:AD:BE:EF:00:00,bridge=vmbr0
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	vm := parseGuestConfig(path, "101", "qemu", "name:")
	if vm.VMID != "101" || vm.Type != "qemu" {
		t.Fatalf("unexpected id/type: %+v", vm)
	}
	if vm.Name != "web01" {
		t.Fatalf("name = %q, want web01", vm.Name)
	}
	want := []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}
	if !reflect.DeepEqual(vm.MACs, want) {
		t.Fatalf("macs = %v, want %v (snapshot MAC must be excluded)", vm.MACs, want)
	}
}

func TestParseGuestConfig_LXCHwaddr(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "200.conf")
	content := `hostname: ct-dns
arch: amd64
net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:BB:CC,ip=dhcp,type=veth
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	vm := parseGuestConfig(path, "200", "lxc", "hostname:")
	if vm.Name != "ct-dns" {
		t.Fatalf("name = %q, want ct-dns", vm.Name)
	}
	if want := []string{"bc:24:11:aa:bb:cc"}; !reflect.DeepEqual(vm.MACs, want) {
		t.Fatalf("macs = %v, want %v", vm.MACs, want)
	}
}

func TestReadPVEConfigs_SkipsNonConfAndNoMAC(t *testing.T) {
	dir := t.TempDir()
	// valid VM
	_ = os.WriteFile(filepath.Join(dir, "101.conf"), []byte("name: a\nnet0: virtio=AA:BB:CC:DD:EE:01,bridge=vmbr0\n"), 0o644)
	// no NIC -> skipped
	_ = os.WriteFile(filepath.Join(dir, "102.conf"), []byte("name: b\nmemory: 512\n"), 0o644)
	// non-conf -> ignored
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("net0: virtio=11:22:33:44:55:66\n"), 0o644)

	got := readPVEConfigs(dir, "qemu", "name:")
	if len(got) != 1 || got[0].VMID != "101" {
		t.Fatalf("got %+v, want only VM 101", got)
	}
}

func TestReadPVEConfigs_MissingDir(t *testing.T) {
	if got := readPVEConfigs(filepath.Join(t.TempDir(), "does-not-exist"), "qemu", "name:"); got != nil {
		t.Fatalf("missing dir should yield nil, got %v", got)
	}
}
