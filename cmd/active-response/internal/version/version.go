package version

import (
	_ "embed"
	"strings"
)

//go:embed version.txt
var embeddedVersion string

var Full = defaultVersion(embeddedVersion)

func defaultVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" {
		return v
	}
	return "0.0.0-dev"
}
