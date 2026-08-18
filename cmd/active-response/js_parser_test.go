package main

import (
	"strings"
	"testing"
)

func TestParseAuthFailures(t *testing.T) {
	lines := []string{
		"Jul 24 12:00:01 host sshd[123]: Failed password for invalid user root from 10.0.0.5 port 22 ssh2",
		"Jul 24 12:00:02 host sshd[123]: Failed password for user admin from 10.0.0.6 port 22 ssh2",
	}
	res := parseAuthFailures(lines, 10)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["user"] != "root" || res[0]["from"] != "10.0.0.5" {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
}

func TestParseRegQueryValues(t *testing.T) {
	out := `
    DevicePath    REG_EXPAND_SZ    system32\\drivers
    Timeout       REG_DWORD        0x1
`
	res := parseRegQueryValues(out, 5)
	if len(res) != 2 {
		t.Fatalf("expected 2 reg values, got %d", len(res))
	}
	if res[0]["name"] != "DevicePath" || res[0]["type"] != "REG_EXPAND_SZ" {
		t.Fatalf("unexpected first value: %+v", res[0])
	}
	if res[1]["data"] != "0x1" {
		t.Fatalf("unexpected second value data: %+v", res[1])
	}
}

func TestParseRegSubkeys(t *testing.T) {
	out := `
HKEY_LOCAL_MACHINE\Software\Foo
    (Default)    REG_SZ
HKEY_LOCAL_MACHINE\Software\Foo\Bar
    Val REG_SZ abc
HKEY_LOCAL_MACHINE\Software\Foo\Baz
`
	subs := parseRegSubkeys(out, "HKEY_LOCAL_MACHINE\\Software\\Foo", 10)
	if len(subs) != 2 {
		t.Fatalf("expected 2 subkeys, got %d", len(subs))
	}
	if subs[0] != "HKEY_LOCAL_MACHINE\\Software\\Foo\\Bar" {
		t.Fatalf("unexpected subkey: %s", subs[0])
	}
}

func TestParseSystemctlShow(t *testing.T) {
	out := `Id=ssh.service
LoadState=loaded
ActiveState=active
SubState=running
Description=OpenSSH server daemon

Id=cron.service
LoadState=loaded
ActiveState=inactive
SubState=dead
Description=Regular background program processing daemon
`
	res := parseSystemctlShow([]byte(out), 10)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["name"] != "ssh.service" || res[0]["active"] != "active" || res[0]["sub"] != "running" {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
	if res[1]["name"] != "cron.service" || res[1]["active"] != "inactive" {
		t.Fatalf("unexpected second entry: %+v", res[1])
	}
}

func TestParseScQuery(t *testing.T) {
	out := `
SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
DISPLAY_NAME: Print Spooler

SERVICE_NAME: wuauserv
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 1  STOPPED
DISPLAY_NAME: Windows Update
`
	res := parseScQuery([]byte(out), 10)
	if len(res) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res))
	}
	if res[0]["name"] != "Spooler" || res[0]["state"] != "4" || !strings.Contains(res[0]["displayName"].(string), "Print") {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
	if res[1]["name"] != "wuauserv" || res[1]["state"] != "1" {
		t.Fatalf("unexpected second entry: %+v", res[1])
	}
}

func TestParseWindowsAutorunReg(t *testing.T) {
	out := `
    OneDrive    REG_SZ    "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background
    SecurityHealth    REG_SZ    %windir%\\system32\\SecurityHealthSystray.exe
`
	res := parseWindowsAutorunRegCtx(out, 5)
	if len(res) != 2 {
		t.Fatalf("expected 2 autoruns, got %d", len(res))
	}
	if res[0]["name"] != "OneDrive" || !strings.Contains(res[0]["command"].(string), "OneDrive.exe") {
		t.Fatalf("unexpected first entry: %+v", res[0])
	}
}
