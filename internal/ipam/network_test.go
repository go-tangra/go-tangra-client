package ipam

import "testing"

func TestIPMINetworkCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		mask string
		want string
	}{
		{"class C", "10.1.112.229", "255.255.255.0", "10.1.112.0/24"},
		{"class B", "172.16.40.5", "255.255.0.0", "172.16.0.0/16"},
		{"/26", "192.168.1.70", "255.255.255.192", "192.168.1.64/26"},
		{"missing mask falls back to /24", "10.1.112.229", "", "10.1.112.0/24"},
		{"invalid mask falls back to /24", "10.1.112.229", "garbage", "10.1.112.0/24"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ipmiNetworkCIDR(tt.ip, tt.mask)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("ipmiNetworkCIDR(%q,%q) = %q, want %q", tt.ip, tt.mask, got, tt.want)
			}
		})
	}
}

func TestIPMINetworkCIDRInvalidIP(t *testing.T) {
	if _, err := ipmiNetworkCIDR("not-an-ip", "255.255.255.0"); err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}
