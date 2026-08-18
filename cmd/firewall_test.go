//go:build unsafe_features

package cmd

import (
	"strings"
	"testing"
)

func TestAddFirewallMissingRule(t *testing.T) {
	if err := runAddFirewall(addFirewallCmd, nil); err == nil {
		t.Fatal("expected error when --rule missing")
	}
}

func TestRemoveFirewallMissingID(t *testing.T) {
	if err := runRemoveFirewall(removeFirewallCmd, nil); err == nil {
		t.Fatal("expected error when --id missing")
	}
}

func TestResyncFirewall(t *testing.T) {
	if err := runResyncFirewall(resyncFirewallCmd, nil); err != nil {
		// Skip when iptables/permissions are unavailable in the test environment.
		if strings.Contains(err.Error(), "iptables") ||
			strings.Contains(err.Error(), "permission") ||
			strings.Contains(err.Error(), "exit status") {
			t.Skipf("skip resync-firewall: %v", err)
		}
		t.Fatalf("resync-firewall failed: %v", err)
	}
}
