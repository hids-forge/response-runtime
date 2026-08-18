package db

import (
	"gorm.io/gorm"
	"time"
)

// FirewallRule represents a persisted OS firewall rule with UUID tagging.
type FirewallRule struct {
	ID        uint       `gorm:"primaryKey"`
	Command   string     // Full OS command used to install the rule
	OsRuleID  string     `gorm:"uniqueIndex"` // UUID tag injected into the OS rule
	AddedAt   time.Time  // Timestamp when the rule was added
	Origin    string     // Subcommand or context that created the rule
	RemovedAt *time.Time // Timestamp when the rule was removed (nil if active)
}

// DB is the GORM database handle for FirewallRule operations.
var DB *gorm.DB
