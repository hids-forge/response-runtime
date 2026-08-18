package main

import "testing"

func TestParseCronLinesUser(t *testing.T) {
	lines := []string{
		"* * * * * /usr/bin/echo hello",
		"  # comment",
		"",
	}
	res := parseCronLines(lines, false, "crontab", 5)
	if len(res) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(res))
	}
	e := res[0]
	if e["minute"] != "*" || e["hour"] != "*" || e["command"] != "/usr/bin/echo hello" {
		t.Fatalf("unexpected cron entry: %+v", e)
	}
	if e["user"] != "" {
		t.Fatalf("expected empty user for user crontab, got %v", e["user"])
	}
}

func TestParseCronLinesSystem(t *testing.T) {
	lines := []string{
		"*/5 0 1 2 3 root /bin/true",
		"@reboot root /bin/start",
	}
	res := parseCronLines(lines, true, "/etc/crontab", 5)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["user"] != "root" || res[0]["command"] != "/bin/true" {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
	if res[1]["minute"] != "@reboot" || res[1]["command"] != "/bin/start" {
		t.Fatalf("unexpected @reboot entry: %+v", res[1])
	}
}

func TestParseLaunchctlList(t *testing.T) {
	out := `PID     Status  Label
-       0       com.apple.Finder
123     0       com.example.task
`
	res := parseLaunchctlList(out, 10)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["label"] != "com.apple.Finder" || res[0]["pid"] != "-" {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
	if res[1]["pid"] != "123" || res[1]["status"] != "0" {
		t.Fatalf("unexpected second entry: %+v", res[1])
	}
}
