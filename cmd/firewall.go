//go:build unsafe_features

package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/hids-forge/response-runtime/pkg/db"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// addFirewallCmd creates a new OS firewall rule with a response-runtime UUID tag.
var addFirewallCmd = &cobra.Command{
	Use:   "add-firewall",
	Short: "Add an OS firewall rule with response-runtime UUID tag",
	RunE:  runAddFirewall,
}

// removeFirewallCmd deletes an OS firewall rule by its response-runtime UUID tag.
var removeFirewallCmd = &cobra.Command{
	Use:   "remove-firewall",
	Short: "Remove an OS firewall rule by response-runtime UUID tag",
	RunE:  runRemoveFirewall,
}

// resyncFirewallCmd reconciles the DB vs. live OS rules using UUID tags.
var resyncFirewallCmd = &cobra.Command{
	Use:   "resync-firewall",
	Short: "Resync firewall rules with DB via response-runtime UUID tags",
	RunE:  runResyncFirewall,
}

func init() {
	// rootCmd.AddCommand(addFirewallCmd, removeFirewallCmd, resyncFirewallCmd)
	addFirewallCmd.Flags().String("rule", "", "OS rule snippet (e.g. 'INPUT -s 10.0.0.5 -j DROP')")
	removeFirewallCmd.Flags().String("id", "", "response-runtime UUID tag of the rule to remove")
}

func runAddFirewall(cmd *cobra.Command, _ []string) error {
	snippet, _ := cmd.Flags().GetString("rule")
	if snippet == "" {
		return fmt.Errorf("--rule is required")
	}
	tag := uuid.NewString()
	osCmd := fmt.Sprintf("iptables -I %s -m comment --comment 'response-runtime:%s'", snippet, tag)
	if err := exec.Command("sh", "-c", osCmd).Run(); err != nil {
		return fmt.Errorf("failed to add firewall rule: %w", err)
	}
	fmt.Printf("Added firewall rule with tag %s\n", tag)
	// Persist to DB
	if err := db.DB.Create(&db.FirewallRule{
		Command:  osCmd,
		OsRuleID: tag,
		AddedAt:  time.Now(),
		Origin:   "add-firewall",
	}).Error; err != nil {
		return fmt.Errorf("failed to save firewall rule to DB: %w", err)
	}
	return nil
}

func runRemoveFirewall(cmd *cobra.Command, _ []string) error {
	tag, _ := cmd.Flags().GetString("id")
	if tag == "" {
		return fmt.Errorf("--id is required")
	}
	osCmd := fmt.Sprintf("iptables -D INPUT -m comment --comment 'response-runtime:%s'", tag)
	if err := exec.Command("sh", "-c", osCmd).Run(); err != nil {
		return fmt.Errorf("failed to remove firewall rule: %w", err)
	}
	fmt.Printf("Removed firewall rule with tag %s\n", tag)
	// Mark RemovedAt in DB
	if err := db.DB.Model(&db.FirewallRule{}).
		Where("os_rule_id = ?", tag).
		Update("removed_at", time.Now()).Error; err != nil {
		log.Printf("failed to mark rule removed in DB: %v", err)
	}
	return nil
}

func runResyncFirewall(_ *cobra.Command, _ []string) error {
	out, err := exec.Command("sh", "-c", "iptables-save").Output()
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	fmt.Println("Live response-runtime rule tags:")
	liveTags := make(map[string]struct{})
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "response-runtime:"); idx != -1 {
			parts := strings.SplitN(line[idx:], "'", 2)
			if len(parts) > 0 {
				tag := parts[0]
				liveTags[tag] = struct{}{}
			}
		}
	}
	fmt.Println("Live response-runtime rule tags:")
	for tag := range liveTags {
		fmt.Println(tag)
	}

	// Reconcile DB rules vs live OS rules
	var rules []db.FirewallRule
	db.DB.Where("removed_at IS NULL").Find(&rules)
	// For each DB rule missing live, reapply
	for _, r := range rules {
		if _, ok := liveTags[r.OsRuleID]; !ok {
			log.Printf("Reapplying missing OS rule: %s", r.OsRuleID)
			if err := exec.Command("sh", "-c", r.Command).Run(); err != nil {
				log.Printf("Failed to reapply rule %s: %v", r.OsRuleID, err)
			} else {
				// clear RemovedAt if previously set
				db.DB.Model(&db.FirewallRule{}).
					Where("os_rule_id = ?", r.OsRuleID).
					Updates(map[string]interface{}{"removed_at": nil, "added_at": time.Now()})
			}
		}
	}
	// For each live tag not in DB, remove orphaned OS rule
	for tag := range liveTags {
		found := false
		for _, r := range rules {
			if r.OsRuleID == tag {
				found = true
				break
			}
		}
		if !found {
			log.Printf("Removing orphan OS rule: %s", tag)
			rmCmd := fmt.Sprintf("iptables -D INPUT -m comment --comment 'response-runtime:%s'", tag)
			if err := exec.Command("sh", "-c", rmCmd).Run(); err != nil {
				log.Printf("Failed to remove orphan rule %s: %v", tag, err)
			}
		}
	}
	return nil
}
