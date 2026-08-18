package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Binject/debug/pe"
	"github.com/dop251/goja"
	gojanode "github.com/dop251/goja_nodejs/require"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pelletier/go-toml/v2"
	"github.com/pierrec/lz4/v4"
	utls "github.com/refraction-networking/utls"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/crypto/ssh"
	ini "gopkg.in/ini.v1"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/andybalholm/brotli"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"github.com/hids-forge/response-runtime/pkg/version"
)

// cache entry for file hashing
type hashCacheEntry struct {
	mtime  time.Time
	size   int64
	md5sum string
	sha256 string
	last   time.Time
}

// sqlite-backed state store (modernc.org/sqlite, no CGO).
type stateDB struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex
}

var (
	stateOnce sync.Once
	stateInst *stateDB
	stateErr  error
)

func defaultStatePath() string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".response-runtime", "state.db")
	}
	return "response-runtime-state.db"
}

func openStateDB() (*stateDB, error) {
	path := defaultStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(0)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=2000;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &stateDB{db: db, path: path}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func getStateDB() (*stateDB, error) {
	stateOnce.Do(func() {
		stateInst, stateErr = openStateDB()
	})
	return stateInst, stateErr
}

func (s *stateDB) initSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, val BLOB);
CREATE TABLE IF NOT EXISTS findings (signature TEXT PRIMARY KEY, ts INTEGER, payload BLOB);
`)
	return err
}

func (s *stateDB) kvGet(key string) (interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var raw []byte
	err := s.db.QueryRow(`SELECT val FROM kv WHERE key=?`, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *stateDB) kvSet(key string, val interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(val)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO kv(key,val) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET val=excluded.val`, key, data)
	return err
}

func (s *stateDB) kvDel(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM kv WHERE key=?`, key)
	return err
}

func (s *stateDB) logFinding(sig string, payload interface{}) (map[string]interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := time.Now()
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO findings(signature, ts, payload) VALUES(?,?,?) ON CONFLICT(signature) DO UPDATE SET ts=excluded.ts, payload=excluded.payload`, sig, ts.UnixMilli(), data)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"signature": sig, "ts": ts, "payload": payload}, nil
}

func (s *stateDB) lastSeen(sig string) (*time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ts int64
	err := s.db.QueryRow(`SELECT ts FROM findings WHERE signature=?`, sig).Scan(&ts)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t := time.UnixMilli(ts)
	return &t, nil
}

// helperDoc holds metadata for each JS helper function.
type helperDoc struct {
	Name        string
	Description string
	Params      []string
}

type pingResult struct {
	Addr   string
	Bytes  int
	Seq    int
	TTL    int
	TimeMs float64
}

type traceHop struct {
	Hop     int
	Host    string
	IP      string
	TimesMs []float64
	Raw     string
}

type appInfo struct {
	Name    string
	Version string
	Source  string
}

type netInterface struct {
	Name   string
	Addr   string
	Net    string
	MTU    int
	Flags  []string
	Mac    string
	Family string
}

type ipRoute struct {
	Dst     string
	Gateway string
	Dev     string
	Metric  int
	Proto   string
	Family  string
}

type pidStats struct {
	Pid        int64
	Name       string
	Exe        string
	CPUPercent float64
	MemRSS     uint64
	MemPercent float32
	UptimeSec  float64
	Status     string
}

type callbackWriter struct {
	vm *goja.Runtime
	fn goja.Callable
}

func (w callbackWriter) Write(p []byte) (int, error) {
	if w.fn != nil && len(p) > 0 {
		_, _ = w.fn(goja.Undefined(), w.vm.ToValue(string(p)))
	}
	return len(p), nil
}

func parseWmicList(lines []string) []map[string]string {
	var res []map[string]string
	cur := map[string]string{}
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			if len(cur) > 0 {
				res = append(res, cur)
				cur = map[string]string{}
			}
			continue
		}
		if parts := strings.SplitN(l, "=", 2); len(parts) == 2 {
			cur[parts[0]] = parts[1]
		}
	}
	if len(cur) > 0 {
		res = append(res, cur)
	}
	return res
}

func parsePingOutput(lines []string) []pingResult {
	var res []pingResult
	reUnix := regexp.MustCompile(`^(\d+)\s+bytes from\s+([^\s:]+):.*icmp_seq=(\d+).*ttl=(\d+).*time=([\d\.]+)\s*ms`)
	reWin := regexp.MustCompile(`^Reply from ([^:]+): bytes=(\d+)\s+time[=<]([\d\.]+)ms\s+TTL=(\d+)`)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := reUnix.FindStringSubmatch(line); len(m) == 6 {
			bytesVal, _ := strconv.Atoi(m[1])
			seq, _ := strconv.Atoi(m[3])
			ttl, _ := strconv.Atoi(m[4])
			tm, _ := strconv.ParseFloat(m[5], 64)
			res = append(res, pingResult{
				Addr:   m[2],
				Bytes:  bytesVal,
				Seq:    seq,
				TTL:    ttl,
				TimeMs: tm,
			})
			continue
		}
		if m := reWin.FindStringSubmatch(line); len(m) == 5 {
			bytesVal, _ := strconv.Atoi(m[2])
			ttl, _ := strconv.Atoi(m[4])
			tm, _ := strconv.ParseFloat(m[3], 64)
			res = append(res, pingResult{
				Addr:   m[1],
				Bytes:  bytesVal,
				TTL:    ttl,
				TimeMs: tm,
			})
		}
	}
	return res
}

func parseTracerouteOutput(lines []string) []traceHop {
	var hops []traceHop
	reHop := regexp.MustCompile(`^\s*(\d+)\s+`)
	reIP := regexp.MustCompile(`\(([^)]+)\)`)
	reTime := regexp.MustCompile(`([0-9.]+)\s*ms`)
	for _, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" {
			continue
		}
		m := reHop.FindStringSubmatch(raw)
		if len(m) < 2 {
			continue
		}
		hopNum, _ := strconv.Atoi(m[1])
		hop := traceHop{Hop: hopNum, Raw: raw}
		if strings.Contains(raw, "*") && !reTime.MatchString(raw) {
			hops = append(hops, hop)
			continue
		}
		if ipMatch := reIP.FindStringSubmatch(raw); len(ipMatch) == 2 {
			hop.IP = strings.TrimSpace(ipMatch[1])
		}
		parts := strings.Fields(raw)
		for _, p := range parts[1:] {
			lp := strings.ToLower(p)
			if strings.Contains(lp, "ms") || lp == "*" {
				continue
			}
			if _, err := strconv.ParseFloat(p, 64); err == nil {
				continue
			}
			if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
				ip := strings.Trim(p, "[]")
				if net.ParseIP(ip) != nil {
					hop.IP = ip
				}
				continue
			}
			if strings.HasPrefix(p, "(") && strings.HasSuffix(p, ")") {
				ip := strings.Trim(p, "()")
				if net.ParseIP(ip) != nil {
					hop.IP = ip
				}
				continue
			}
			// first non-ms token becomes host
			if hop.Host == "" {
				hop.Host = p
			}
		}
		if hop.IP == "" && net.ParseIP(hop.Host) != nil {
			hop.IP = hop.Host
		}
		if strings.HasPrefix(strings.ToLower(hop.Host), "request") {
			hop.Host = ""
		}
		for _, tm := range reTime.FindAllStringSubmatch(raw, -1) {
			if len(tm) == 2 {
				if v, err := strconv.ParseFloat(tm[1], 64); err == nil {
					hop.TimesMs = append(hop.TimesMs, v)
				}
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

func parseInstalledTabLines(lines []string, source string) []appInfo {
	var out []appInfo
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		fields := strings.Fields(l)
		if len(fields) < 2 {
			parts := strings.Split(l, "\t")
			if len(parts) >= 2 {
				fields = parts
			}
		}
		if len(fields) >= 2 {
			out = append(out, appInfo{Name: fields[0], Version: strings.Join(fields[1:], " "), Source: source})
		}
	}
	return out
}

func parseIPAddrJSON(data []byte) []netInterface {
	type addr struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		Prefix    int    `json:"prefixlen"`
		Broadcast string `json:"broadcast"`
	}
	type iface struct {
		Index    int      `json:"ifindex"`
		Name     string   `json:"ifname"`
		MTU      int      `json:"mtu"`
		Flags    []string `json:"flags"`
		AddrInfo []addr   `json:"addr_info"`
		Address  string   `json:"address"`
	}
	var parsed []iface
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}
	var out []netInterface
	for _, i := range parsed {
		base := netInterface{
			Name:  i.Name,
			MTU:   i.MTU,
			Flags: i.Flags,
			Mac:   i.Address,
		}
		for _, a := range i.AddrInfo {
			ni := base
			ni.Family = a.Family
			ni.Addr = a.Local
			if a.Local != "" && a.Prefix > 0 {
				ni.Net = fmt.Sprintf("%s/%d", a.Local, a.Prefix)
			}
			out = append(out, ni)
		}
		// If no addr_info, still record interface
		if len(i.AddrInfo) == 0 {
			out = append(out, base)
		}
	}
	return out
}

func parseIfconfig(lines []string) []netInterface {
	var out []netInterface
	var current *netInterface
	reIface := regexp.MustCompile(`^([a-zA-Z0-9._:-]+):`)
	reAddr := regexp.MustCompile(`inet\s+([0-9.]+)`)
	reAddr6 := regexp.MustCompile(`inet6\s+([0-9a-fA-F:]+)/(\d+)`)
	reMac := regexp.MustCompile(`ether\s+([0-9a-fA-F:]+)`)
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if m := reIface.FindStringSubmatch(line); len(m) == 2 {
			if current != nil {
				out = append(out, *current)
			}
			current = &netInterface{Name: m[1]}
			continue
		}
		if current == nil {
			continue
		}
		if m := reAddr.FindStringSubmatch(line); len(m) >= 2 {
			ni := *current
			ni.Addr = m[1]
			ni.Family = "inet"
			out = append(out, ni)
		}
		if m := reAddr6.FindStringSubmatch(line); len(m) == 3 {
			ni := *current
			ni.Addr = m[1]
			ni.Family = "inet6"
			ni.Net = fmt.Sprintf("%s/%s", m[1], m[2])
			out = append(out, ni)
		}
		if m := reMac.FindStringSubmatch(line); len(m) == 2 {
			current.Mac = m[1]
		}
	}
	if current != nil {
		out = append(out, *current)
	}
	return out
}

func parseIpconfig(lines []string) []netInterface {
	var out []netInterface
	var current *netInterface
	reName := regexp.MustCompile(`^([A-Za-z].*):$`)
	reIPv4 := regexp.MustCompile(`IPv4 Address.*?:\s*([\d.]+)`)
	reIPv6 := regexp.MustCompile(`IPv6 Address.*?:\s*([0-9a-fA-F:]+)`)
	reMAC := regexp.MustCompile(`Physical Address.*?:\s*([0-9A-Fa-f-]+)`)
	for _, l := range lines {
		line := strings.TrimSpace(l)
		if m := reName.FindStringSubmatch(line); len(m) == 2 && !strings.HasPrefix(line, "Tunnel adapter") {
			if current != nil {
				out = append(out, *current)
			}
			current = &netInterface{Name: m[1]}
			continue
		}
		if current == nil {
			continue
		}
		if m := reIPv4.FindStringSubmatch(line); len(m) == 2 {
			ni := *current
			ni.Addr = m[1]
			ni.Family = "inet"
			out = append(out, ni)
		}
		if m := reIPv6.FindStringSubmatch(line); len(m) == 2 {
			ni := *current
			ni.Addr = m[1]
			ni.Family = "inet6"
			out = append(out, ni)
		}
		if m := reMAC.FindStringSubmatch(line); len(m) == 2 {
			current.Mac = strings.ReplaceAll(m[1], "-", ":")
		}
	}
	if current != nil {
		out = append(out, *current)
	}
	return out
}

func parseIPRouteJSON(data []byte) []ipRoute {
	type route struct {
		Dst      string `json:"dst"`
		Gateway  string `json:"gateway"`
		Dev      string `json:"dev"`
		Protocol string `json:"protocol"`
		Metric   *int   `json:"metric"`
		Family   int    `json:"family"`
	}
	var rs []route
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil
	}
	var out []ipRoute
	for _, r := range rs {
		fam := ""
		switch r.Family {
		case 2:
			fam = "inet"
		case 10:
			fam = "inet6"
		}
		m := 0
		if r.Metric != nil {
			m = *r.Metric
		}
		out = append(out, ipRoute{
			Dst:     r.Dst,
			Gateway: r.Gateway,
			Dev:     r.Dev,
			Metric:  m,
			Proto:   r.Protocol,
			Family:  fam,
		})
	}
	return out
}

func parseNetstatRoute(lines []string) []ipRoute {
	var out []ipRoute
	for _, l := range lines {
		fields := strings.Fields(strings.TrimSpace(l))
		if len(fields) < 3 {
			continue
		}
		// Try Linux `netstat -rn` layout: Destination Gateway Genmask Flags MSS Window irtt Iface
		if net.ParseIP(fields[0]) != nil {
			route := ipRoute{
				Dst:     fields[0],
				Gateway: fields[1],
				Dev:     fields[len(fields)-1],
			}
			out = append(out, route)
			continue
		}
	}
	return out
}

func matchPathInsensitive(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func getPidStats(p *process.Process) (*pidStats, error) {
	name, _ := p.Name()
	exe, _ := p.Exe()
	status, _ := p.Status()
	cpu, _ := p.CPUPercent()
	memInfo, _ := p.MemoryInfo()
	memPct, _ := p.MemoryPercent()
	ct, _ := p.CreateTime()
	uptime := 0.0
	if ct > 0 {
		uptime = time.Since(time.Unix(0, ct*int64(time.Millisecond))).Seconds()
	}
	return &pidStats{
		Pid:        int64(p.Pid),
		Name:       name,
		Exe:        exe,
		Status:     strings.Join(status, "|"),
		CPUPercent: cpu,
		MemRSS:     memInfo.RSS,
		MemPercent: memPct,
		UptimeSec:  uptime,
	}, nil
}

// runner abstracts command execution; can be overridden for testing.
type runner interface {
	Run() error
	CombinedOutput() ([]byte, error)
}

type JsData struct {
	Script        string `json:"script"`
	MqttURL       string `json:"mqtt-url"`
	MqttUsername  string `json:"mqtt-username"`
	MqttPassword  string `json:"mqtt-password"`
	Agent         string `json:"agent"`
	Manager       string `json:"manager"`
	CorrelationID string `json:"correlation_id"`
	ReplyTo       string `json:"reply_to"`
	ProgressTo    string `json:"progress_to"`
	DebugTo       string `json:"debug_to"`
}

var (
	hashCache     = make(map[string]*hashCacheEntry)
	hashCacheMu   sync.Mutex
	yaraLoaded    bool
	yaraErr       string
	yaraRules     []string
	lookupNS      = net.LookupNS
	lookupHost    = net.LookupHost
	progressTopic string
	debugTopic    string
)

// helperDocs lists all built-in JS helpers with name, description, and parameter names.
var helperDocs = []helperDoc{}

const (
	maxProcList        = 512
	maxConnList        = 1024
	maxDirEntries      = 2000
	maxDirDepth        = 5
	maxHashBytes       = 50 * 1024 * 1024 // 50 MB hash cap
	maxStringsBytes    = 5 * 1024 * 1024  // 5 MB strings cap
	maxStringsResults  = 500
	maxEntropyFileRead = 2 * 1024 * 1024 // 2 MB entropy cap
	maxHTTPBody        = 128 * 1024      // 128 KB body cap
	maxPortsChecked    = 64
	maxListEntries     = 200
	maxAuthLines       = 500
	maxRegEntries      = 200
	maxWhoisBytes      = 64 * 1024
	maxMemSearchTotal  = 16 * 1024 * 1024 // 16 MB total scan cap
	maxMemSearchHits   = 64
	maxPEBytes         = 8 * 1024 * 1024 // 8 MB cap for PE parsing
	maxServiceHashes   = 10              // hash up to 10 services per call
	maxServiceHashSize = 30 * 1024 * 1024
	randAlphabet       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// exportProcInfo normalizes process metadata with best-effort error handling.
func exportProcInfo(p *process.Process) map[string]interface{} {
	info := map[string]interface{}{
		"pid":        int64(p.Pid),
		"name":       "",
		"exe":        "",
		"cmdline":    []string{},
		"username":   "",
		"ppid":       int64(0),
		"createTime": int64(0),
		"status":     "",
		"cpuPct":     float64(0),
		"memPct":     float32(0),
		"cwd":        "",
	}
	if name, err := p.Name(); err == nil {
		info["name"] = name
	}
	if exe, err := p.Exe(); err == nil {
		info["exe"] = exe
	}
	if cmd, err := p.CmdlineSlice(); err == nil {
		info["cmdline"] = cmd
	}
	if user, err := p.Username(); err == nil {
		info["username"] = user
	}
	if ppid, err := p.Ppid(); err == nil {
		info["ppid"] = int64(ppid)
	}
	if ct, err := p.CreateTime(); err == nil {
		info["createTime"] = ct
	}
	if st, err := p.Status(); err == nil {
		info["status"] = st
	}
	if cpu, err := p.CPUPercent(); err == nil {
		info["cpuPct"] = cpu
	}
	if mem, err := p.MemoryPercent(); err == nil {
		info["memPct"] = mem
	}
	if cwd, err := p.Cwd(); err == nil {
		info["cwd"] = cwd
	}
	return info
}

// exportConnections normalizes a list of ConnectionStat to JS-friendly maps.
func exportConnections(conns []gnet.ConnectionStat) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(conns))
	for i, c := range conns {
		if i >= maxConnList {
			break
		}
		entry := map[string]interface{}{
			"pid":    c.Pid,
			"status": c.Status,
			"family": c.Family,
			"type":   c.Type,
			"laddr": map[string]interface{}{
				"ip":   c.Laddr.IP,
				"port": c.Laddr.Port,
			},
			"raddr": map[string]interface{}{
				"ip":   c.Raddr.IP,
				"port": c.Raddr.Port,
			},
		}
		out = append(out, entry)
	}
	return out
}

// computeFileHashes hashes a file up to maxBytes.
func computeFileHashes(path string, maxBytes int64) (string, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if maxBytes > 0 && st.Size() > maxBytes {
		return "", "", fmt.Errorf("file too large for hashing (%d bytes)", st.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := md5.New()
	h2 := sha256.New()
	if _, err := io.Copy(io.MultiWriter(h, h2), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(h.Sum(nil)), hex.EncodeToString(h2.Sum(nil)), nil
}

// hashFileWith provides SHA1 when requested, bounded by maxHashBytes.
func hashFileWith(path string, algo string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", fmt.Errorf("path is a directory")
	}
	if maxHashBytes > 0 && st.Size() > maxHashBytes {
		return "", fmt.Errorf("file too large for hashing (%d bytes)", st.Size())
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch strings.ToLower(algo) {
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported algo: %s", algo)
	}
}

// computeEntropy returns Shannon entropy of the provided bytes.
func computeEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}
	var ent float64
	total := float64(len(data))
	for _, c := range counts {
		p := float64(c) / total
		ent -= p * math.Log2(p)
	}
	return ent
}

func currentTelemetry() (float64, uint64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	cpuPct := 0.0
	p, _ := process.NewProcess(int32(os.Getpid()))
	if p != nil {
		if pct, err := p.CPUPercent(); err == nil {
			cpuPct = pct
		}
	}
	return cpuPct, m.Alloc
}

func peMachineString(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "arm"
	default:
		return fmt.Sprintf("0x%x", m)
	}
}

func peSubsystemString(sub uint16) string {
	switch sub {
	case 1:
		return "native"
	case 2:
		return "windows_gui"
	case 3:
		return "windows_cui"
	case 9:
		return "windows_ce"
	case 10:
		return "efi_application"
	case 14:
		return "xbox"
	default:
		return fmt.Sprintf("0x%x", sub)
	}
}

func peInfo(path string) (map[string]interface{}, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}
	if st.Size() > maxPEBytes {
		return nil, fmt.Errorf("file too large for PE parsing (%d bytes)", st.Size())
	}
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := map[string]interface{}{
		"machine":          peMachineString(f.FileHeader.Machine),
		"machineRaw":       fmt.Sprintf("0x%x", f.FileHeader.Machine),
		"timestamp":        time.Unix(int64(f.FileHeader.TimeDateStamp), 0),
		"numberOfSections": int(f.FileHeader.NumberOfSections),
		"characteristics":  fmt.Sprintf("0x%x", f.FileHeader.Characteristics),
	}

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info["is64"] = true
		info["entry"] = fmt.Sprintf("0x%x", oh.AddressOfEntryPoint)
		info["imageBase"] = fmt.Sprintf("0x%x", oh.ImageBase)
		info["subsystem"] = peSubsystemString(oh.Subsystem)
		info["sizeOfImage"] = oh.SizeOfImage
	case *pe.OptionalHeader32:
		info["is64"] = false
		info["entry"] = fmt.Sprintf("0x%x", oh.AddressOfEntryPoint)
		info["imageBase"] = fmt.Sprintf("0x%x", oh.ImageBase)
		info["subsystem"] = peSubsystemString(oh.Subsystem)
		info["sizeOfImage"] = oh.SizeOfImage
	default:
		info["subsystem"] = "unknown"
	}

	var sections []map[string]interface{}
	for _, s := range f.Sections {
		sec := map[string]interface{}{
			"name":            strings.Trim(s.Name, "\x00"),
			"virtualSize":     s.VirtualSize,
			"virtualAddress":  s.VirtualAddress,
			"size":            s.Size,
			"offset":          s.Offset,
			"characteristics": fmt.Sprintf("0x%x", s.Characteristics),
		}
		if data, err := s.Data(); err == nil {
			sec["entropy"] = computeEntropy(data)
		} else {
			sec["error"] = err.Error()
		}
		sections = append(sections, sec)
		if len(sections) >= maxListEntries {
			break
		}
	}
	info["sections"] = sections

	if libs, err := f.ImportedLibraries(); err == nil {
		info["dlls"] = libs
	} else {
		info["dllsError"] = err.Error()
	}

	if dirs, _, _, err := f.ImportDirectoryTable(); err == nil {
		var imports []map[string]interface{}
		for _, d := range dirs {
			entry := map[string]interface{}{
				"dll":              d.DllName,
				"timestamp":        time.Unix(int64(d.TimeDateStamp), 0),
				"originalFirstRVA": d.OriginalFirstThunk,
				"firstThunkRVA":    d.FirstThunk,
			}
			imports = append(imports, entry)
			if len(imports) >= maxListEntries {
				break
			}
		}
		info["imports"] = imports
	} else {
		info["importsError"] = err.Error()
	}

	if syms, err := f.ImportedSymbols(); err == nil {
		if len(syms) > maxListEntries {
			syms = syms[:maxListEntries]
		}
		info["symbols"] = syms
	} else {
		info["symbolsError"] = err.Error()
	}

	return info, nil
}

func parseSystemctlShow(out []byte, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, block := range strings.Split(string(out), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		entry := map[string]interface{}{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "Id=") {
				entry["name"] = strings.TrimPrefix(line, "Id=")
			} else if strings.HasPrefix(line, "LoadState=") {
				entry["load"] = strings.TrimPrefix(line, "LoadState=")
			} else if strings.HasPrefix(line, "ActiveState=") {
				entry["active"] = strings.TrimPrefix(line, "ActiveState=")
			} else if strings.HasPrefix(line, "SubState=") {
				entry["sub"] = strings.TrimPrefix(line, "SubState=")
			} else if strings.HasPrefix(line, "Description=") {
				entry["description"] = strings.TrimPrefix(line, "Description=")
			}
		}
		if len(entry) > 0 {
			res = append(res, entry)
			if len(res) >= limit {
				break
			}
		}
	}
	return res
}

func parseScQuery(out []byte, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	entry := map[string]interface{}{}
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "SERVICE_NAME:") {
			if len(entry) > 0 {
				res = append(res, entry)
				if len(res) >= limit {
					break
				}
			}
			entry = map[string]interface{}{"name": strings.TrimSpace(strings.TrimPrefix(l, "SERVICE_NAME:"))}
		} else if strings.HasPrefix(l, "STATE") {
			parts := strings.Fields(l)
			if len(parts) >= 3 {
				entry["state"] = parts[2]
			}
		} else if strings.HasPrefix(l, "DISPLAY_NAME") {
			entry["displayName"] = strings.TrimSpace(strings.TrimPrefix(l, "DISPLAY_NAME:"))
		}
	}
	if len(entry) > 0 && len(res) < limit {
		res = append(res, entry)
	}
	return res
}

func parseWindowsAutorunReg(ctx context.Context, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	roots := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	}
	for _, root := range roots {
		cmd := exec.CommandContext(ctx, "reg", "query", root)
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		res = append(res, parseWindowsAutorunRegCtx(string(out), limit-len(res))...)
		if len(res) >= limit {
			return res[:limit]
		}
	}
	return res
}

func parseWindowsAutorunRegCtx(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "REG_SZ") {
			fields := strings.Fields(l)
			if len(fields) >= 3 {
				res = append(res, map[string]interface{}{
					"name":    fields[0],
					"command": strings.Join(fields[2:], " "),
					"type":    "registry",
				})
				if len(res) >= limit {
					return res
				}
			}
		}
	}
	return res
}

// parseAuthFailures extracts auth failure entries from syslog-style lines.
func parseAuthFailures(lines []string, limit int) []map[string]interface{} {
	var entries []map[string]interface{}
	for _, l := range lines {
		if strings.Contains(l, "Failed password") || strings.Contains(l, "authentication failure") {
			parts := strings.Fields(l)
			msg := l
			user := ""
			from := ""
			for i, p := range parts {
				if p == "user" && i+1 < len(parts) {
					user = strings.Trim(parts[i+1], "[]")
				}
				if p == "from" && i+1 < len(parts) {
					from = parts[i+1]
				}
			}
			entries = append(entries, map[string]interface{}{
				"line": msg,
				"user": user,
				"from": from,
			})
			if len(entries) >= limit {
				break
			}
		}
	}
	return entries
}

func parseRegQueryValues(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "REG_") {
			fields := strings.Fields(l)
			if len(fields) >= 3 {
				entry := map[string]interface{}{
					"name": fields[0],
					"type": fields[1],
					"data": strings.Join(fields[2:], " "),
				}
				res = append(res, entry)
				if len(res) >= limit {
					return res
				}
			}
		}
	}
	return res
}

func parseRegSubkeys(out string, root string, limit int) []string {
	var subs []string
	normRoot := strings.ReplaceAll(root, "\\\\", "\\")
	for _, l := range strings.Split(out, "\n") {
		orig := strings.TrimSpace(l)
		normLine := strings.ReplaceAll(orig, "\\\\", "\\")
		if strings.HasPrefix(normLine, "HKEY") && normLine != normRoot {
			if normRoot == "" || strings.HasPrefix(normLine, normRoot) {
				subs = append(subs, normLine)
				if len(subs) >= limit {
					return subs
				}
			}
		}
	}
	return subs
}

func parseSystemctlDetails(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, block := range strings.Split(out, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		entry := map[string]interface{}{}
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "Id=") {
				entry["name"] = strings.TrimPrefix(line, "Id=")
			} else if strings.HasPrefix(line, "ActiveState=") {
				entry["active"] = strings.TrimPrefix(line, "ActiveState=")
			} else if strings.HasPrefix(line, "SubState=") {
				entry["sub"] = strings.TrimPrefix(line, "SubState=")
			} else if strings.HasPrefix(line, "Description=") {
				entry["description"] = strings.TrimPrefix(line, "Description=")
			} else if strings.HasPrefix(line, "FragmentPath=") {
				entry["unitFile"] = strings.TrimPrefix(line, "FragmentPath=")
			} else if strings.HasPrefix(line, "ExecStart=") {
				val := strings.TrimPrefix(line, "ExecStart=")
				if idx := strings.Index(val, "path="); idx != -1 {
					rest := val[idx+len("path="):]
					semi := strings.Index(rest, " ")
					if semi == -1 {
						semi = strings.Index(rest, ";")
					}
					if semi > 0 {
						entry["path"] = strings.TrimSpace(rest[:semi])
					}
				}
			}
		}
		if len(entry) > 0 {
			res = append(res, entry)
			if len(res) >= limit {
				break
			}
		}
	}
	return res
}

func parseWindowsDnsCache(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	cur := map[string]interface{}{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Record Name") {
			if len(cur) > 0 {
				res = append(res, cur)
				if len(res) >= limit {
					return res
				}
			}
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				cur = map[string]interface{}{"name": strings.TrimSpace(parts[1])}
			} else {
				cur = map[string]interface{}{}
			}
		} else if strings.HasPrefix(l, "Record Type") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				cur["type"] = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(l, "Time To Live") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				cur["ttl"] = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(strings.ToLower(l), "record data") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				cur["data"] = strings.TrimSpace(parts[1])
			}
		}
	}
	if len(cur) > 0 && len(res) < limit {
		res = append(res, cur)
	}
	return res
}

func parseDscacheutilHosts(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	cur := map[string]interface{}{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "name:") {
			if len(cur) > 0 {
				res = append(res, cur)
				if len(res) >= limit {
					return res
				}
			}
			cur = map[string]interface{}{"name": strings.TrimSpace(strings.TrimPrefix(l, "name:"))}
		} else if strings.HasPrefix(l, "ip_address:") {
			cur["data"] = strings.TrimSpace(strings.TrimPrefix(l, "ip_address:"))
		}
	}
	if len(cur) > 0 && len(res) < limit {
		res = append(res, cur)
	}
	return res
}

func parseNscdHosts(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "name:") {
			parts := strings.Fields(l)
			if len(parts) >= 2 {
				res = append(res, map[string]interface{}{"name": parts[1]})
				if len(res) >= limit {
					break
				}
			}
		} else if strings.HasPrefix(l, "ip_address:") && len(res) > 0 {
			res[len(res)-1]["data"] = strings.TrimSpace(strings.TrimPrefix(l, "ip_address:"))
		}
	}
	return res
}

func parseIptablesSave(out string, prefix string, limit int) []string {
	var ips []string
	for _, l := range strings.Split(out, "\n") {
		if idx := strings.Index(l, prefix); idx != -1 {
			rest := l[idx+len(prefix):]
			if end := strings.Index(rest, "\""); end != -1 {
				ips = append(ips, rest[:end])
				if len(ips) >= limit {
					break
				}
			}
		}
	}
	return ips
}

func parseNetshFirewall(out string, limit int) []string {
	var ips []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "Rule Name:") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 && strings.HasPrefix(strings.TrimSpace(parts[1]), "response-runtime:BLOCK_") {
				ip := strings.TrimPrefix(strings.TrimSpace(parts[1]), "response-runtime:BLOCK_")
				ips = append(ips, ip)
				if len(ips) >= limit {
					break
				}
			}
		}
	}
	return ips
}

func parsePfctlTable(out string, limit int) []string {
	entries := strings.Fields(out)
	if len(entries) > limit {
		return entries[:limit]
	}
	return entries
}

// parseCronLines normalizes crontab entries into structured maps.
func parseCronLines(lines []string, hasUser bool, source string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, l := range lines {
		lt := strings.TrimSpace(l)
		if lt == "" || strings.HasPrefix(lt, "#") || strings.HasPrefix(lt, ";") {
			continue
		}
		if strings.Contains(lt, "=") && !strings.HasPrefix(lt, "@") {
			// environment assignment, skip
			continue
		}
		fields := strings.Fields(lt)
		if len(fields) < 6 && !strings.HasPrefix(lt, "@") {
			continue
		}
		entry := map[string]interface{}{
			"source": source,
		}
		if strings.HasPrefix(lt, "@") {
			// @reboot user cmd...
			if len(fields) < 2 {
				continue
			}
			entry["minute"] = fields[0]
			entry["hour"] = ""
			entry["dom"] = ""
			entry["month"] = ""
			entry["dow"] = ""
			if hasUser {
				entry["user"] = fields[1]
				entry["command"] = strings.Join(fields[2:], " ")
			} else {
				entry["user"] = ""
				entry["command"] = strings.Join(fields[1:], " ")
			}
		} else {
			if hasUser {
				if len(fields) < 7 {
					continue
				}
				entry["minute"], entry["hour"], entry["dom"], entry["month"], entry["dow"] = fields[0], fields[1], fields[2], fields[3], fields[4]
				entry["user"] = fields[5]
				entry["command"] = strings.Join(fields[6:], " ")
			} else {
				entry["minute"], entry["hour"], entry["dom"], entry["month"], entry["dow"] = fields[0], fields[1], fields[2], fields[3], fields[4]
				entry["user"] = ""
				entry["command"] = strings.Join(fields[5:], " ")
			}
		}
		res = append(res, entry)
		if len(res) >= limit {
			break
		}
	}
	return res
}

// parseLaunchctlList converts launchctl list output into structured entries.
func parseLaunchctlList(out string, limit int) []map[string]interface{} {
	var res []map[string]interface{}
	for _, l := range strings.Split(out, "\n") {
		fields := strings.Fields(l)
		if len(fields) != 3 {
			continue
		}
		pidField := fields[0]
		if pidField == "PID" { // header
			continue
		}
		if _, err := strconv.Atoi(fields[1]); err != nil && fields[1] != "-" {
			continue
		}
		entry := map[string]interface{}{
			"pid":    pidField,
			"status": fields[1],
			"label":  fields[2],
		}
		res = append(res, entry)
		if len(res) >= limit {
			break
		}
	}
	return res
}

func truncateRuleName(rule string) string {
	if len(rule) > 32 {
		return rule[:32]
	}
	return rule
}

// parseHostsContent parses hosts file content into structured entries.
func parseHostsContent(content string, limit int) []map[string]interface{} {
	lines := strings.Split(content, "\n")
	entries := make([]map[string]interface{}, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		var comment string
		if idx := strings.Index(l, "#"); idx != -1 {
			comment = strings.TrimSpace(l[idx+1:])
			l = strings.TrimSpace(l[:idx])
		} else if idx := strings.Index(l, ";"); idx != -1 {
			comment = strings.TrimSpace(l[idx+1:])
			l = strings.TrimSpace(l[:idx])
		}
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		hostnames := fields[1:]
		entries = append(entries, map[string]interface{}{
			"ip":        ip,
			"hostnames": hostnames,
			"comment":   comment,
		})
		if len(entries) >= limit {
			break
		}
	}
	return entries
}

// whoisSummary performs a simple whois lookup and returns trimmed fields.
func whoisSummary(target string) (map[string]interface{}, error) {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(target + "\r\n")); err != nil {
		return nil, err
	}
	data, _ := io.ReadAll(io.LimitReader(conn, int64(maxWhoisBytes)))
	lines := strings.Split(string(data), "\n")
	out := map[string]interface{}{}
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), "refer:") {
			out["refer"] = strings.TrimSpace(strings.TrimPrefix(l, "refer:"))
		}
		if strings.HasPrefix(strings.ToLower(l), "organisation:") {
			out["org"] = strings.TrimSpace(strings.TrimPrefix(l, "organisation:"))
		}
		if len(out) >= 2 {
			break
		}
	}
	out["raw"] = strings.TrimSpace(string(data))
	return out, nil
}

// httpFingerprintInternal fetches minimal HTTP fingerprints with bounded body.
func httpFingerprintInternal(u string, bodyLimit int) (map[string]interface{}, error) {
	res := map[string]interface{}{}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "response-runtime/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	res["status"] = resp.StatusCode
	headers := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	res["headers"] = headers
	if bodyLimit <= 0 || bodyLimit > maxHTTPBody {
		bodyLimit = maxHTTPBody
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, int64(bodyLimit)))
	sum := sha256.Sum256(b)
	res["bodyHash"] = fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
	title := ""
	if strings.Contains(strings.ToLower(headers["Content-Type"]), "html") {
		if idx := strings.Index(strings.ToLower(string(b)), "<title>"); idx != -1 {
			end := strings.Index(strings.ToLower(string(b[idx+7:])), "</title>")
			if end != -1 {
				title = strings.TrimSpace(string(b[idx+7 : idx+7+end]))
			}
		}
	}
	res["title"] = title
	return res, nil
}

// tlsFingerprintInternal collects basic cert metadata.
func tlsFingerprintInternal(host string, port int, timeoutMs int) (map[string]interface{}, error) {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return map[string]interface{}{}, nil
	}
	c := state.PeerCertificates[0]
	return map[string]interface{}{
		"subject":    c.Subject.String(),
		"issuer":     c.Issuer.String(),
		"notBefore":  c.NotBefore,
		"notAfter":   c.NotAfter,
		"sans":       c.DNSNames,
		"commonName": c.Subject.CommonName,
	}, nil
}

// dnsTrace performs a basic trace by querying NS and A/AAAA records and returning structured entries.
func dnsTrace(name string) ([]map[string]interface{}, error) {
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53"}
	var out []map[string]interface{}
	for _, r := range resolvers {
		ns, err := lookupNS(name)
		entryNS := map[string]interface{}{
			"resolver": r,
			"type":     "NS",
		}
		if err != nil {
			entryNS["error"] = err.Error()
		} else {
			var nsHosts []string
			for _, n := range ns {
				nsHosts = append(nsHosts, n.Host)
			}
			entryNS["records"] = nsHosts
		}
		out = append(out, entryNS)
		if len(out) >= maxListEntries {
			return out, nil
		}

		ips, err := lookupHost(name)
		entryA := map[string]interface{}{
			"resolver": r,
			"type":     "A/AAAA",
		}
		if err != nil {
			entryA["error"] = err.Error()
		} else {
			entryA["records"] = ips
		}
		out = append(out, entryA)
		if len(out) >= maxListEntries {
			return out, nil
		}
	}
	return out, nil
}

// computeJA3 builds a custom ClientHello and returns the JA3 hash.
func computeJA3(host string, port int) (string, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	config := &utls.Config{ServerName: host}
	rawConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer rawConn.Close()

	helloID := utls.HelloFirefox_Auto
	uconn := utls.UClient(rawConn, config, helloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		return "", err
	}
	raw := uconn.HandshakeState.Hello.Raw
	ja3Str, err := buildJA3FromRaw(raw)
	if err != nil {
		return "", err
	}
	return hashJA3(ja3Str), nil
}

func joinU16(nums []uint16) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, "-")
}

func joinU8(nums []uint8) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, "-")
}

func hashJA3(ja3 string) string {
	sum := md5.Sum([]byte(ja3))
	return hex.EncodeToString(sum[:])
}

// buildJA3FromRaw parses a ClientHello (handshake body) and builds a JA3 string.
func buildJA3FromRaw(raw []byte) (string, error) {
	// skip record header if present
	if len(raw) > 5 && raw[0] == 0x16 {
		raw = raw[5:]
	}
	if len(raw) < 42 || raw[0] != 0x01 {
		return "", fmt.Errorf("not a clienthello")
	}
	// skip handshake header (1 type + 3 len)
	pos := 4
	if pos+2 > len(raw) {
		return "", fmt.Errorf("truncated version")
	}
	vers := uint16(raw[pos])<<8 | uint16(raw[pos+1])
	pos += 2
	// random
	pos += 32
	if pos >= len(raw) {
		return "", fmt.Errorf("truncated random")
	}
	// session id
	sessLen := int(raw[pos])
	pos++
	pos += sessLen
	if pos+2 > len(raw) {
		return "", fmt.Errorf("truncated cipher suites")
	}
	csLen := int(raw[pos])<<8 | int(raw[pos+1])
	pos += 2
	var ciphers []uint16
	for i := 0; i < csLen; i += 2 {
		if pos+i+1 >= len(raw) {
			return "", fmt.Errorf("truncated cipher entry")
		}
		ciphers = append(ciphers, uint16(raw[pos+i])<<8|uint16(raw[pos+i+1]))
	}
	pos += csLen
	if pos >= len(raw) {
		return "", fmt.Errorf("truncated compression")
	}
	compLen := int(raw[pos])
	pos++
	pos += compLen
	if pos+2 > len(raw) {
		return "", fmt.Errorf("no extensions")
	}
	extLen := int(raw[pos])<<8 | int(raw[pos+1])
	pos += 2
	if pos+extLen > len(raw) {
		extLen = len(raw) - pos
	}
	var (
		exts   []uint16
		curves []uint16
		points []uint8
	)
	end := pos + extLen
	for pos+4 <= end {
		extType := uint16(raw[pos])<<8 | uint16(raw[pos+1])
		exts = append(exts, extType)
		elen := int(raw[pos+2])<<8 | int(raw[pos+3])
		pos += 4
		if pos+elen > end {
			break
		}
		data := raw[pos : pos+elen]
		switch extType {
		case 10: // supported groups
			if len(data) >= 2 {
				clen := int(data[0])<<8 | int(data[1])
				for i := 0; i+1 < clen && 2+i < len(data); i += 2 {
					curves = append(curves, uint16(data[2+i])<<8|uint16(data[3+i]))
				}
			}
		case 11: // ec_point_formats
			if len(data) >= 1 {
				plen := int(data[0])
				for i := 0; i < plen && 1+i < len(data); i++ {
					points = append(points, data[1+i])
				}
			}
		}
		pos += elen
	}
	ja3 := strings.Join([]string{
		fmt.Sprintf("%d", vers),
		joinU16(ciphers),
		joinU16(exts),
		joinU16(curves),
		joinU8(points),
	}, ",")
	return ja3, nil
}

var (
	// osType specifies the platform for OS-specific helpers (overrideable in tests)
	osType = runtime.GOOS
	// ejectRunner executes external commands for ejectUsb (mockable in tests)
	ejectRunner = func(name string, args ...string) runner { return exec.Command(name, args...) }
	// firewallRunner executes external commands for firewall helpers (mockable in tests)
	firewallRunner = func(name string, args ...string) runner { return exec.Command(name, args...) }
	timeout        = 30 * time.Second
)

func handleJs(payload helper.Payload) {
	publishTopic = ""
	log.Println("Start running JS.")
	var jsData JsData
	json.Unmarshal(payload.Parameters.Alert.Data, &jsData)
	if jsData.Script == "" {
		log.Println("Script is empty")
	} else {
		log.Printf("Script: %s", jsData.Script)
	}

	progressTopic = ""
	debugTopic = ""
	configureMQTT(mqttConfig{
		MqttURL:       jsData.MqttURL,
		MqttUsername:  jsData.MqttUsername,
		MqttPassword:  jsData.MqttPassword,
		Agent:         jsData.Agent,
		Manager:       jsData.Manager,
		ReplyTo:       jsData.ReplyTo,
		CorrelationID: jsData.CorrelationID,
		ProgressTo:    jsData.ProgressTo,
		DebugTo:       jsData.DebugTo,
	})
	progressTopic = strings.TrimSpace(jsData.ProgressTo)
	debugTopic = strings.TrimSpace(jsData.DebugTo)

	alertObj := map[string]interface{}{}
	_ = json.Unmarshal(payload.Parameters.Alert.Data, &alertObj)
	result, progress := runJsWithContext(jsData.Script, alertObj)
	if result != "" {
		sendBackResponse([]byte(result))
	}
	_ = progress // reserved for future forwarding if needed
}

func runJs(script string) (string, []map[string]interface{}) {
	return runJsWithContext(script, nil)
}

func runJsWithContext(script string, alertCtx map[string]interface{}) (string, []map[string]interface{}) {
	// Initialize Goja VM and require support
	vm := goja.New()
	req := gojanode.NewRegistry()
	req.Enable(vm)
	// Inject helper functions into the VM
	var progress []map[string]interface{}
	RegisterHelpers(vm, &progress)

	var logs []string
	console := vm.NewObject()
	console.Set("log", func(call goja.FunctionCall) goja.Value {
		parts := make([]interface{}, len(call.Arguments))
		for i, a := range call.Arguments {
			parts[i] = a.Export()
		}
		logs = append(logs, fmt.Sprint(parts...))
		return goja.Undefined()
	})
	vm.Set("console", console)

	if alertCtx != nil {
		vm.Set("alert", alertCtx)
	}

	// Execute script under timeout guard
	done := make(chan struct{})
	var runErr error
	go func() {
		_, runErr = vm.RunString(script)
		close(done)
	}()
	select {
	case <-done:
		if runErr != nil {
			log.Println("script error:", runErr)
			return fmt.Sprintf("js error: %v", runErr), progress
		}
		if len(logs) > 0 {
			log.Println(strings.Join(logs, "\n"))
			return strings.Join(logs, "\n"), progress
		}
		return "js completed", progress
	case <-time.After(timeout):
		log.Println("script execution timed out")
		return "js execution timed out", progress
	}

}

// registerHelpers injects Go-backed helper functions into the JS VM.
// RegisterHelpers injects Go-backed helper functions into the JavaScript VM.
func RegisterHelpers(vm *goja.Runtime, progress *[]map[string]interface{}) {
	addHelper := func(name, desc string, params []string, setter func()) {
		helperDocs = append(helperDocs, helperDoc{Name: name, Description: desc, Params: params})
		setter()
	}

	toBytesWithEncoding := func(val goja.Value, stringEncoding string) ([]byte, error) {
		var raw []byte
		if err := vm.ExportTo(val, &raw); err == nil && raw != nil {
			return raw, nil
		}
		switch x := val.Export().(type) {
		case goja.ArrayBuffer:
			return x.Bytes(), nil
		case *goja.ArrayBuffer:
			return x.Bytes(), nil
		case []byte:
			return x, nil
		case string:
			enc := strings.ToLower(strings.TrimSpace(stringEncoding))
			if enc == "" || enc == "utf8" || enc == "utf-8" || enc == "text" {
				return []byte(x), nil
			}
			switch enc {
			case "base64":
				return base64.StdEncoding.DecodeString(x)
			case "hex":
				return hex.DecodeString(strings.TrimSpace(x))
			default:
				return nil, fmt.Errorf("unsupported string encoding %q", enc)
			}
		default:
			return nil, fmt.Errorf("unsupported input type %T", x)
		}
	}

	encodeWithEncoding := func(data []byte, outEnc string) (interface{}, error) {
		enc := strings.ToLower(strings.TrimSpace(outEnc))
		switch enc {
		case "", "buffer", "arraybuffer", "bytes":
			return vm.NewArrayBuffer(data), nil
		case "base64":
			return base64.StdEncoding.EncodeToString(data), nil
		case "hex":
			return hex.EncodeToString(data), nil
		case "utf8", "utf-8", "text":
			return string(data), nil
		default:
			return nil, fmt.Errorf("unsupported encoding %q", outEnc)
		}
	}

	addHelper("readFile", "Read a file; default returns Uint8Array, optional encoding returns string", []string{"path", "encoding?"}, func() {
		vm.Set("readFile", func(path string, encodingOpt ...string) (interface{}, error) {
			if !jsFileReadEnabled {
				return nil, fmt.Errorf("readFile is disabled in this build")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			enc := ""
			if len(encodingOpt) > 0 {
				enc = strings.ToLower(strings.TrimSpace(encodingOpt[0]))
			}
			return encodeWithEncoding(b, enc)
		})
		vm.Set("readTextFile", func(path string) (string, error) {
			if !jsFileReadEnabled {
				return "", fmt.Errorf("readTextFile is disabled in this build")
			}
			b, err := os.ReadFile(path)
			return string(b), err
		})
	})
	addHelper("helpers", "List available helpers (name, description, params)", []string{}, func() {
		vm.Set("helpers", func() []helperDoc {
			return helperDocs
		})
	})
	addHelper("whoami", "Return current username", []string{}, func() {
		vm.Set("whoami", func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		})
	})
	addHelper("uname", "Return OS/platform info", []string{}, func() {
		vm.Set("uname", func() map[string]string {
			hn, _ := os.Hostname()
			return map[string]string{
				"os":       runtime.GOOS,
				"arch":     runtime.GOARCH,
				"version":  runtime.Version(),
				"hostname": hn,
			}
		})
	})

	// state API (sqlite-backed via modernc.org/sqlite).
	stateObj := vm.NewObject()
	stateObj.Set("kvGet", func(key string) (interface{}, error) {
		db, err := getStateDB()
		if err != nil {
			return nil, err
		}
		return db.kvGet(key)
	})
	stateObj.Set("kvSet", func(key string, val interface{}) error {
		db, err := getStateDB()
		if err != nil {
			return err
		}
		return db.kvSet(key, val)
	})
	stateObj.Set("kvDel", func(key string) error {
		db, err := getStateDB()
		if err != nil {
			return err
		}
		return db.kvDel(key)
	})
	stateObj.Set("logFinding", func(sig string, payload interface{}) (map[string]interface{}, error) {
		db, err := getStateDB()
		if err != nil {
			return nil, err
		}
		return db.logFinding(sig, payload)
	})
	stateObj.Set("lastSeen", func(sig string) (string, error) {
		db, err := getStateDB()
		if err != nil {
			return "", err
		}
		ts, err := db.lastSeen(sig)
		if err != nil {
			return "", err
		}
		if ts == nil {
			return "", nil
		}
		return ts.Format(time.RFC3339Nano), nil
	})
	vm.Set("state", stateObj)

	// firewall object: block/unblock/list/flush IP-based blocks
	fw := vm.NewObject()
	fw.Set("blockIp", func(ip string) error {
		tag := "response-runtime:BLOCK_" + ip
		switch osType {
		case "linux":
			return firewallRunner("iptables", "-I", "INPUT",
				"-m", "comment", "--comment", tag,
				"-s", ip, "-j", "DROP").Run()
		case "windows":
			rule := fmt.Sprintf("name=%s", tag)
			return firewallRunner("netsh", "advfirewall", "firewall", "add", "rule",
				rule, "dir=in", "action=block", fmt.Sprintf("remoteip=%s", ip)).Run()
		case "darwin":
			return firewallRunner("pfctl", "-t", "response_runtime", "-T", "add", ip).Run()
		default:
			return fmt.Errorf("firewall.blockIp: unsupported platform %s", osType)
		}
	})
	fw.Set("unblockIp", func(ip string) error {
		tag := "response-runtime:BLOCK_" + ip
		switch osType {
		case "linux":
			return firewallRunner("iptables", "-D", "INPUT",
				"-m", "comment", "--comment", tag,
				"-s", ip, "-j", "DROP").Run()
		case "windows":
			return firewallRunner("netsh", "advfirewall", "firewall", "delete", "rule",
				fmt.Sprintf("name=%s", tag), fmt.Sprintf("remoteip=%s", ip)).Run()
		case "darwin":
			return firewallRunner("pfctl", "-t", "response_runtime", "-T", "delete", ip).Run()
		default:
			return fmt.Errorf("firewall.unblockIp: unsupported platform %s", osType)
		}
	})
	fw.Set("listBlockedIps", func() ([]string, error) {
		switch osType {
		case "linux":
			out, err := firewallRunner("iptables-save").CombinedOutput()
			if err != nil {
				return nil, err
			}
			return parseIptablesSave(string(out), "comment \"response-runtime:BLOCK_", maxListEntries), nil
		case "windows":
			out, err := firewallRunner("netsh", "advfirewall", "firewall", "show", "rule", "name=response-runtime:BLOCK_*", "verbose").CombinedOutput()
			if err != nil {
				return nil, err
			}
			return parseNetshFirewall(string(out), maxListEntries), nil
		case "darwin":
			out, err := firewallRunner("pfctl", "-t", "response_runtime", "-T", "show").CombinedOutput()
			if err != nil {
				return nil, err
			}
			return parsePfctlTable(string(out), maxListEntries), nil
		default:
			return nil, fmt.Errorf("firewall.listBlockedIps: unsupported platform %s", osType)
		}
	})
	fw.Set("flushBlockList", func() error {
		ips, err := fw.Get("listBlockedIps").Export().([]string)
		if !err {
			return fmt.Errorf("firewall.flushBlockList: listBlockedIps failed or returned wrong type")
		}
		for _, ip := range ips {
			tag := "response-runtime:BLOCK_" + ip
			switch osType {
			case "linux":
				if err := firewallRunner("iptables", "-D", "INPUT",
					"-m", "comment", "--comment", tag,
					"-s", ip, "-j", "DROP").Run(); err != nil {
					return err
				}
			case "windows":
				if err := firewallRunner("netsh", "advfirewall", "firewall", "delete", "rule",
					fmt.Sprintf("name=%s", tag), fmt.Sprintf("remoteip=%s", ip)).Run(); err != nil {
					return err
				}
			case "darwin":
				if err := firewallRunner("pfctl", "-t", "response_runtime", "-T", "delete", ip).Run(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("firewall.flushBlockList: unsupported platform %s", osType)
			}
		}
		// Also clean Windows exe-based rules
		if osType == "windows" {
			_ = firewallRunner("netsh", "advfirewall", "firewall", "delete", "rule", "name=response-runtime-exe-block-*").Run()
		}
		return nil
	})
	// Windows-only executable blocking
	fw.Set("blockExe", func(path string) error {
		if osType != "windows" {
			return fmt.Errorf("firewall.blockExe: unsupported platform %s", osType)
		}
		p := strings.TrimSpace(path)
		if p == "" {
			return fmt.Errorf("firewall.blockExe: path required")
		}
		rule := fmt.Sprintf("name=response-runtime-exe-block-%x", md5.Sum([]byte(p)))
		return firewallRunner("netsh", "advfirewall", "firewall", "add", "rule",
			rule, "dir=out", "action=block", "program="+p).Run()
	})
	fw.Set("unblockExe", func(path string) error {
		if osType != "windows" {
			return fmt.Errorf("firewall.unblockExe: unsupported platform %s", osType)
		}
		p := strings.TrimSpace(path)
		if p == "" {
			return fmt.Errorf("firewall.unblockExe: path required")
		}
		rule := fmt.Sprintf("name=response-runtime-exe-block-%x", md5.Sum([]byte(p)))
		return firewallRunner("netsh", "advfirewall", "firewall", "delete", "rule", rule).Run()
	})
	vm.Set("firewall", fw)
	if jsUnsafeFeaturesEnabled {
		addHelper("writeFile", "Write data (Uint8Array/ArrayBuffer/string) to a file", []string{"path", "data", "encoding?"}, func() {
			vm.Set("writeFile", func(path string, data goja.Value, encodingOpt ...string) error {
				var b []byte
				enc := ""
				if len(encodingOpt) > 0 {
					enc = strings.ToLower(strings.TrimSpace(encodingOpt[0]))
				}
				b, err := toBytesWithEncoding(data, enc)
				if err != nil {
					return err
				}
				return os.WriteFile(path, b, 0644)
			})
		})
		addHelper("writeTextFile", "Write UTF-8 text to a file", []string{"path", "data"}, func() {
			vm.Set("writeTextFile", func(path, data string) error {
				return os.WriteFile(path, []byte(data), 0644)
			})
		})
		addHelper("importModule", "Load a JS module from file or http(s) URL (CommonJS-style)", []string{"path"}, func() {
			vm.Set("importModule", func(path string) (goja.Value, error) {
				p := strings.TrimSpace(path)
				if p == "" {
					return nil, fmt.Errorf("importModule: path required")
				}
				var src []byte
				if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
					if !jsHTTPImportEnabled {
						return nil, fmt.Errorf("importModule: HTTP import is disabled in this build")
					}
					client := &http.Client{Timeout: 10 * time.Second}
					resp, err := client.Get(p)
					if err != nil {
						return nil, err
					}
					defer resp.Body.Close()
					src, err = io.ReadAll(resp.Body)
					if err != nil {
						return nil, err
					}
				} else {
					b, err := os.ReadFile(p)
					if err != nil {
						return nil, err
					}
					src = b
				}
				wrapped := fmt.Sprintf("(function(module, exports, require){\n%s\n})", string(src))
				fnVal, err := vm.RunString(wrapped)
				if err != nil {
					return nil, err
				}
				fn, ok := goja.AssertFunction(fnVal)
				if !ok {
					return nil, fmt.Errorf("importModule: not a function")
				}
				moduleObj := vm.NewObject()
				exportsObj := vm.NewObject()
				moduleObj.Set("exports", exportsObj)
				reqVal := vm.Get("require")
				_, err = fn(goja.Undefined(), moduleObj, exportsObj, reqVal)
				if err != nil {
					return nil, err
				}
				return moduleObj.Get("exports"), nil
			})
		})
	} else {
		addHelper("writeFile", "Write data (Uint8Array/ArrayBuffer/string) to a file", []string{"path", "data", "encoding?"}, func() {
			vm.Set("writeFile", func(path string, data goja.Value, encodingOpt ...string) error {
				_ = path
				_ = data
				_ = encodingOpt
				return fmt.Errorf("writeFile is disabled in this build")
			})
		})
		addHelper("writeTextFile", "Write UTF-8 text to a file", []string{"path", "data"}, func() {
			vm.Set("writeTextFile", func(path, data string) error {
				_ = path
				_ = data
				return fmt.Errorf("writeTextFile is disabled in this build")
			})
		})
		addHelper("importModule", "Load a JS module from file or http(s) URL (CommonJS-style)", []string{"path"}, func() {
			vm.Set("importModule", func(path string) (goja.Value, error) {
				_ = path
				return nil, fmt.Errorf("importModule is disabled in this build")
			})
		})
	}
	if jsHTTPClientEnabled {
		addHelper("httpGet", "HTTP GET with optional response encoding", []string{"url", "encoding?"}, func() {
			vm.Set("httpGet", func(url string, encodingOpt ...string) (interface{}, error) {
				resp, err := http.Get(url)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				enc := "utf8"
				if len(encodingOpt) > 0 && strings.TrimSpace(encodingOpt[0]) != "" {
					enc = strings.ToLower(strings.TrimSpace(encodingOpt[0]))
				}
				return encodeWithEncoding(b, enc)
			})
		})
		addHelper("httpPost", "HTTP POST with options (body/json/headers/timeout, body encoding selectable)", []string{"url", "opts"}, func() {
			vm.Set("httpPost", func(urlStr string, opts map[string]interface{}) (map[string]interface{}, error) {
				method := "POST"
				if v, ok := opts["method"].(string); ok && v != "" {
					method = strings.ToUpper(strings.TrimSpace(v))
				}
				respEncoding := "utf8"
				if v, ok := opts["encoding"].(string); ok && v != "" {
					respEncoding = strings.ToLower(strings.TrimSpace(v))
				}
				timeoutMs := int64(10000)
				if v, ok := opts["timeoutMs"].(int64); ok && v > 0 {
					timeoutMs = v
				} else if v, ok := opts["timeoutMs"].(float64); ok && v > 0 {
					timeoutMs = int64(v)
				}

				var bodyBytes []byte
				if v, ok := opts["json"]; ok {
					b, err := json.Marshal(v)
					if err != nil {
						return nil, fmt.Errorf("httpPost json marshal: %w", err)
					}
					bodyBytes = b
					if opts["headers"] == nil {
						opts["headers"] = map[string]interface{}{}
					}
					if hmap, ok := opts["headers"].(map[string]interface{}); ok {
						if _, exists := hmap["Content-Type"]; !exists {
							hmap["Content-Type"] = "application/json"
						}
					}
				} else if v, ok := opts["body"]; ok {
					enc := ""
					if encOpt, ok := opts["bodyEncoding"].(string); ok {
						enc = encOpt
					}
					var err error
					bodyBytes, err = toBytesWithEncoding(vm.ToValue(v), enc)
					if err != nil {
						return nil, fmt.Errorf("httpPost body: %w", err)
					}
				}

				req, err := http.NewRequest(method, urlStr, bytes.NewReader(bodyBytes))
				if err != nil {
					return nil, err
				}
				if hmap, ok := opts["headers"].(map[string]interface{}); ok {
					for k, val := range hmap {
						req.Header.Set(k, fmt.Sprint(val))
					}
				}

				client := &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond}
				resp, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				b, err := io.ReadAll(resp.Body)
				if err != nil {
					return nil, err
				}
				bodyVal, err := encodeWithEncoding(b, respEncoding)
				if err != nil {
					return nil, err
				}
				hdrs := map[string]interface{}{}
				for k, vals := range resp.Header {
					if len(vals) > 0 {
						hdrs[k] = vals[0]
					}
				}
				return map[string]interface{}{
					"statusCode": resp.StatusCode,
					"status":     resp.Status,
					"headers":    hdrs,
					"body":       bodyVal,
				}, nil
			})
		})
	} else {
		addHelper("httpGet", "HTTP GET with optional response encoding", []string{"url", "encoding?"}, func() {
			vm.Set("httpGet", func(url string, encodingOpt ...string) (interface{}, error) {
				_ = url
				_ = encodingOpt
				return nil, fmt.Errorf("httpGet is disabled in this build")
			})
		})
		addHelper("httpPost", "HTTP POST with options (body/json/headers/timeout, body encoding selectable)", []string{"url", "opts"}, func() {
			vm.Set("httpPost", func(urlStr string, opts map[string]interface{}) (map[string]interface{}, error) {
				_ = urlStr
				_ = opts
				return nil, fmt.Errorf("httpPost is disabled in this build")
			})
		})
	}

	addHelper("ping", "Ping a host count times; returns array of replies (optional callback per reply)", []string{"host", "count?", "callback?"}, func() {
		vm.Set("ping", func(call goja.FunctionCall) goja.Value {
			if !jsNetworkProbesEnabled {
				panic(vm.ToValue("ping is disabled in this build"))
			}
			if len(call.Arguments) == 0 {
				panic(vm.NewTypeError("ping: host required"))
			}
			host := call.Argument(0).String()
			count := 4
			if len(call.Arguments) > 1 {
				if c, ok := call.Argument(1).Export().(int64); ok && c > 0 {
					count = int(c)
				} else if c, ok := call.Argument(1).Export().(float64); ok && c > 0 {
					count = int(c)
				}
			}
			if count <= 0 {
				count = 4
			}
			if count > 10 {
				count = 10
			}

			var cb goja.Callable
			if len(call.Arguments) > 2 {
				if fn, ok := goja.AssertFunction(call.Arguments[2]); ok {
					cb = fn
				}
			}

			var args []string
			switch osType {
			case "windows":
				args = []string{"-n", fmt.Sprintf("%d", count), host}
			default:
				args = []string{"-n", "-c", fmt.Sprintf("%d", count), host}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(count*2)*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "ping", args...)
			out, err := cmd.CombinedOutput()
			lines := strings.Split(string(out), "\n")
			results := parsePingOutput(lines)
			if cb != nil {
				for _, r := range results {
					obj := vm.NewObject()
					obj.Set("addr", r.Addr)
					obj.Set("bytes", r.Bytes)
					if r.Seq > 0 {
						obj.Set("seq", r.Seq)
					}
					if r.TTL > 0 {
						obj.Set("ttl", r.TTL)
					}
					obj.Set("timeMs", r.TimeMs)
					_, _ = cb(goja.Undefined(), obj)
				}
			}
			arr := make([]map[string]interface{}, 0, len(results))
			for _, r := range results {
				entry := map[string]interface{}{
					"addr":   r.Addr,
					"bytes":  r.Bytes,
					"timeMs": r.TimeMs,
				}
				if r.Seq > 0 {
					entry["seq"] = r.Seq
				}
				if r.TTL > 0 {
					entry["ttl"] = r.TTL
				}
				arr = append(arr, entry)
			}
			if err != nil {
				// Return parsed replies alongside error string
				resp := map[string]interface{}{
					"results": arr,
					"error":   err.Error(),
				}
				return vm.ToValue(resp)
			}
			return vm.ToValue(arr)
		})
	})

	addHelper("traceroute", "Run traceroute/tracert and return hops (optional callback per hop)", []string{"host", "maxHops?", "callback?"}, func() {
		vm.Set("traceroute", func(call goja.FunctionCall) goja.Value {
			if !jsNetworkProbesEnabled {
				panic(vm.ToValue("traceroute is disabled in this build"))
			}
			if len(call.Arguments) == 0 {
				panic(vm.NewTypeError("traceroute: host required"))
			}
			host := call.Argument(0).String()
			maxHops := 30
			if len(call.Arguments) > 1 {
				if n, ok := call.Argument(1).Export().(int64); ok && n > 0 {
					maxHops = int(n)
				} else if n, ok := call.Argument(1).Export().(float64); ok && n > 0 {
					maxHops = int(n)
				}
			}
			if maxHops <= 0 {
				maxHops = 30
			}
			if maxHops > 64 {
				maxHops = 64
			}

			var cb goja.Callable
			if len(call.Arguments) > 2 {
				if fn, ok := goja.AssertFunction(call.Arguments[2]); ok {
					cb = fn
				}
			}

			var args []string
			switch osType {
			case "windows":
				args = []string{"-d", "-h", fmt.Sprintf("%d", maxHops), host}
			default:
				args = []string{"-n", "-m", fmt.Sprintf("%d", maxHops), host}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(maxHops)*time.Second)
			defer cancel()
			cmdName := "traceroute"
			if osType == "windows" {
				cmdName = "tracert"
			}
			cmd := exec.CommandContext(ctx, cmdName, args...)
			out, err := cmd.CombinedOutput()
			lines := strings.Split(string(out), "\n")
			hops := parseTracerouteOutput(lines)
			if cb != nil {
				for _, h := range hops {
					obj := vm.NewObject()
					obj.Set("hop", h.Hop)
					obj.Set("host", h.Host)
					obj.Set("ip", h.IP)
					times := make([]interface{}, 0, len(h.TimesMs))
					for _, v := range h.TimesMs {
						times = append(times, v)
					}
					obj.Set("timesMs", times)
					obj.Set("raw", h.Raw)
					_, _ = cb(goja.Undefined(), obj)
				}
			}
			arr := make([]map[string]interface{}, 0, len(hops))
			for _, h := range hops {
				entry := map[string]interface{}{
					"hop":     h.Hop,
					"host":    h.Host,
					"ip":      h.IP,
					"timesMs": h.TimesMs,
					"raw":     h.Raw,
				}
				arr = append(arr, entry)
			}
			if err != nil {
				resp := map[string]interface{}{
					"hops":  arr,
					"error": err.Error(),
				}
				return vm.ToValue(resp)
			}
			return vm.ToValue(arr)
		})
	})

	addHelper("listInstalledApps", "List installed applications/packages (cross-platform best effort)", []string{}, func() {
		vm.Set("listInstalledApps", func() (interface{}, error) {
			var apps []appInfo
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			add := func(items []appInfo) {
				apps = append(apps, items...)
			}
			switch osType {
			case "linux":
				if path, _ := exec.LookPath("dpkg-query"); path != "" {
					cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n")
					out, err := cmd.Output()
					if err == nil {
						add(parseInstalledTabLines(strings.Split(string(out), "\n"), "dpkg"))
						break
					}
				}
				if path, _ := exec.LookPath("rpm"); path != "" {
					cmd := exec.CommandContext(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
					out, err := cmd.Output()
					if err == nil {
						add(parseInstalledTabLines(strings.Split(string(out), "\n"), "rpm"))
						break
					}
				}
				if path, _ := exec.LookPath("pacman"); path != "" {
					cmd := exec.CommandContext(ctx, "pacman", "-Q")
					out, err := cmd.Output()
					if err == nil {
						add(parseInstalledTabLines(strings.Split(string(out), "\n"), "pacman"))
						break
					}
				}
			case "darwin":
				if path, _ := exec.LookPath("brew"); path != "" {
					cmd := exec.CommandContext(ctx, "brew", "list", "--versions")
					out, err := cmd.Output()
					if err == nil {
						add(parseInstalledTabLines(strings.Split(string(out), "\n"), "brew"))
					}
				}
			case "windows":
				cmd := exec.CommandContext(ctx, "wmic", "product", "get", "Name,Version", "/format:list")
				out, err := cmd.CombinedOutput()
				records := parseWmicList(strings.Split(string(out), "\n"))
				for _, r := range records {
					apps = append(apps, appInfo{Name: r["Name"], Version: r["Version"], Source: "wmic"})
				}
				if err != nil && len(apps) == 0 {
					return nil, fmt.Errorf("winWmicQuery failed: %v", err)
				}
			}

			result := make([]map[string]interface{}, 0, len(apps))
			for _, a := range apps {
				if a.Name == "" {
					continue
				}
				entry := map[string]interface{}{
					"name":    a.Name,
					"version": a.Version,
					"source":  a.Source,
				}
				result = append(result, entry)
			}
			return result, nil
		})
	})

	addHelper("listNetworkInterfaces", "List network interfaces and addresses (cross-platform best effort)", []string{}, func() {
		vm.Set("listNetworkInterfaces", func() (interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var ifs []netInterface
			switch osType {
			case "linux":
				if path, _ := exec.LookPath("ip"); path != "" {
					cmd := exec.CommandContext(ctx, "ip", "-json", "addr")
					if out, err := cmd.Output(); err == nil {
						ifs = parseIPAddrJSON(out)
					}
				}
				if len(ifs) == 0 {
					if path, _ := exec.LookPath("ifconfig"); path != "" {
						out, err := exec.CommandContext(ctx, "ifconfig").CombinedOutput()
						if err == nil {
							ifs = parseIfconfig(strings.Split(string(out), "\n"))
						}
					}
				}
			case "darwin":
				if path, _ := exec.LookPath("ifconfig"); path != "" {
					out, err := exec.CommandContext(ctx, "ifconfig").CombinedOutput()
					if err == nil {
						ifs = parseIfconfig(strings.Split(string(out), "\n"))
					}
				}
			case "windows":
				cmd := exec.CommandContext(ctx, "ipconfig", "/all")
				out, err := cmd.CombinedOutput()
				if err == nil {
					ifs = parseIpconfig(strings.Split(string(out), "\n"))
				}
			}
			result := make([]map[string]interface{}, 0, len(ifs))
			for _, n := range ifs {
				entry := map[string]interface{}{
					"name":   n.Name,
					"addr":   n.Addr,
					"net":    n.Net,
					"mtu":    n.MTU,
					"flags":  n.Flags,
					"mac":    n.Mac,
					"family": n.Family,
				}
				result = append(result, entry)
			}
			return result, nil
		})
	})

	addHelper("listIpRoutes", "List IP routes (best effort per OS)", []string{}, func() {
		vm.Set("listIpRoutes", func() (interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var routes []ipRoute
			switch osType {
			case "linux":
				if path, _ := exec.LookPath("ip"); path != "" {
					if out, err := exec.CommandContext(ctx, "ip", "-json", "route").Output(); err == nil {
						routes = parseIPRouteJSON(out)
					}
				}
				if len(routes) == 0 {
					if out, err := exec.CommandContext(ctx, "netstat", "-rn").CombinedOutput(); err == nil {
						routes = parseNetstatRoute(strings.Split(string(out), "\n"))
					}
				}
			case "darwin":
				if out, err := exec.CommandContext(ctx, "netstat", "-rn").CombinedOutput(); err == nil {
					routes = parseNetstatRoute(strings.Split(string(out), "\n"))
				}
			case "windows":
				if out, err := exec.CommandContext(ctx, "route", "print").CombinedOutput(); err == nil {
					routes = parseNetstatRoute(strings.Split(string(out), "\n"))
				}
			}
			result := make([]map[string]interface{}, 0, len(routes))
			for _, r := range routes {
				entry := map[string]interface{}{
					"dst":     r.Dst,
					"gateway": r.Gateway,
					"dev":     r.Dev,
					"metric":  r.Metric,
					"proto":   r.Proto,
					"family":  r.Family,
				}
				result = append(result, entry)
			}
			return result, nil
		})
	})

	addHelper("pidToPath", "Return executable path and cmdline for a PID", []string{"pid"}, func() {
		vm.Set("pidToPath", func(pid int64) (map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			exe, _ := p.Exe()
			cmd, _ := p.CmdlineSlice()
			name, _ := p.Name()
			return map[string]interface{}{
				"pid":     pid,
				"name":    name,
				"exe":     exe,
				"cmdline": cmd,
			}, nil
		})
	})

	addHelper("pathToPid", "Find PIDs matching an executable path", []string{"path"}, func() {
		vm.Set("pathToPid", func(path string) ([]int64, error) {
			target := strings.TrimSpace(path)
			if target == "" {
				return nil, fmt.Errorf("pathToPid: path required")
			}
			pids, err := process.Pids()
			if err != nil {
				return nil, err
			}
			var out []int64
			for _, pid := range pids {
				p, err := process.NewProcess(pid)
				if err != nil {
					continue
				}
				exe, err := p.Exe()
				if err != nil || exe == "" {
					continue
				}
				if matchPathInsensitive(exe, target) {
					out = append(out, int64(pid))
				}
			}
			return out, nil
		})
	})

	addHelper("getPidStats", "Return CPU/memory/uptime info for a PID", []string{"pid"}, func() {
		vm.Set("getPidStats", func(pid int64) (map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			stats, err := getPidStats(p)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"pid":        stats.Pid,
				"name":       stats.Name,
				"exe":        stats.Exe,
				"cpuPercent": stats.CPUPercent,
				"memRSS":     stats.MemRSS,
				"memPercent": stats.MemPercent,
				"uptimeSec":  stats.UptimeSec,
				"status":     stats.Status,
			}, nil
		})
	})

	addHelper("killProcess", "Terminate a process by PID (best effort)", []string{"pid", "signal?"}, func() {
		vm.Set("killProcess", func(pid int64, sigOpt ...string) (map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			var killErr error
			if len(sigOpt) > 0 && strings.TrimSpace(sigOpt[0]) != "" {
				sigStr := strings.TrimSpace(sigOpt[0])
				switch sigStr {
				case "term", "terminate", "sigterm":
					killErr = p.Terminate()
				case "kill", "sigkill":
					killErr = p.Kill()
				default:
					killErr = fmt.Errorf("unsupported signal %q", sigStr)
				}
			} else {
				killErr = p.Kill()
			}
			res := map[string]interface{}{"pid": pid}
			if killErr != nil {
				res["error"] = killErr.Error()
			} else {
				res["killed"] = true
			}
			return res, nil
		})
	})

	addHelper("suspendProcess", "Suspend/stop a process by PID (best effort)", []string{"pid"}, func() {
		vm.Set("suspendProcess", func(pid int64) (map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			err = p.Suspend()
			res := map[string]interface{}{"pid": pid}
			if err != nil {
				res["error"] = err.Error()
			} else {
				res["suspended"] = true
			}
			return res, nil
		})
	})

	addHelper("resumeProcess", "Resume a previously suspended process by PID (best effort)", []string{"pid"}, func() {
		vm.Set("resumeProcess", func(pid int64) (map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			err = p.Resume()
			res := map[string]interface{}{"pid": pid}
			if err != nil {
				res["error"] = err.Error()
			} else {
				res["resumed"] = true
			}
			return res, nil
		})
	})

	addHelper("winWmicQuery", "Run a WMIC query (Windows only, safe allowlist) and return parsed list output", []string{"query"}, func() {
		vm.Set("winWmicQuery", func(query string) (interface{}, error) {
			if osType != "windows" {
				return nil, fmt.Errorf("winWmicQuery: only available on windows")
			}
			q := strings.TrimSpace(query)
			if q == "" {
				return nil, fmt.Errorf("winWmicQuery: query required")
			}
			// Simple allowlist to avoid injection: alnum, space, underscore, dash, slash, dot, equals, comma, colon
			if !regexp.MustCompile(`^[A-Za-z0-9_\\/:,=\\.\\-\\s]+$`).MatchString(q) {
				return nil, fmt.Errorf("winWmicQuery: query contains unsupported characters")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "wmic", strings.Fields(q)...)
			cmd.Args = append(cmd.Args, "/format:list")
			out, err := cmd.CombinedOutput()
			results := parseWmicList(strings.Split(string(out), "\n"))
			if err != nil {
				return map[string]interface{}{
					"results": results,
					"error":   err.Error(),
				}, nil
			}
			return results, nil
		})
	})

	if jsUnsafeWithAuthEnabled {
		addHelper("sshExec", "Execute a command over SSH (ssh://user:pass@host:port or opts)", []string{"urlOrHost", "opts"}, func() {
			vm.Set("sshExec", func(urlOrHost string, opts map[string]interface{}) (map[string]interface{}, error) {
				var user, pass, host string
				port := 22
				command := ""
				encoding := "utf8"
				stderrEncoding := "utf8"
				timeoutMs := int64(10000)
				var stdinData []byte
				var envVars map[string]string
				var keyPem, passphrase string

				if u, err := url.Parse(urlOrHost); err == nil && u.Host != "" {
					host = u.Hostname()
					if p := u.Port(); p != "" {
						if n, _ := strconv.Atoi(p); n > 0 {
							port = n
						}
					}
					if u.User != nil {
						user = u.User.Username()
						pass, _ = u.User.Password()
					}
					if cmd := u.Query().Get("command"); cmd != "" {
						command = cmd
					}
				} else {
					host = urlOrHost
				}

				if v, ok := opts["user"].(string); ok && v != "" {
					user = v
				}
				if v, ok := opts["password"].(string); ok {
					pass = v
				}
				if v, ok := opts["passphrase"].(string); ok {
					passphrase = v
				}
				if v, ok := opts["key"].(string); ok {
					keyPem = v
				}
				if v, ok := opts["port"].(int64); ok && v > 0 {
					port = int(v)
				} else if v, ok := opts["port"].(float64); ok && v > 0 {
					port = int(v)
				}
				if v, ok := opts["command"].(string); ok && v != "" {
					command = v
				}
				if v, ok := opts["encoding"].(string); ok && v != "" {
					encoding = strings.ToLower(strings.TrimSpace(v))
				}
				if v, ok := opts["stderrEncoding"].(string); ok && v != "" {
					stderrEncoding = strings.ToLower(strings.TrimSpace(v))
				}
				var cbOut, cbErr goja.Callable
				if v, ok := opts["stdoutCallback"]; ok {
					if fn, ok := goja.AssertFunction(vm.ToValue(v)); ok {
						cbOut = fn
					}
				}
				if v, ok := opts["stderrCallback"]; ok {
					if fn, ok := goja.AssertFunction(vm.ToValue(v)); ok {
						cbErr = fn
					}
				}
				if v, ok := opts["stdin"].(string); ok {
					stdinData = []byte(v)
				}
				if v, ok := opts["stdinBase64"].(string); ok && len(stdinData) == 0 {
					if data, err := base64.StdEncoding.DecodeString(v); err == nil {
						stdinData = data
					}
				}
				if v, ok := opts["env"].(map[string]interface{}); ok {
					envVars = map[string]string{}
					for k, val := range v {
						envVars[k] = fmt.Sprint(val)
					}
				}
				if v, ok := opts["timeoutMs"].(int64); ok && v > 0 {
					timeoutMs = v
				} else if v, ok := opts["timeoutMs"].(float64); ok && v > 0 {
					timeoutMs = int64(v)
				}

				if host == "" || user == "" || command == "" {
					return nil, fmt.Errorf("sshExec: host, user, and command are required")
				}

				var auths []ssh.AuthMethod
				if keyPem != "" {
					var signer ssh.Signer
					var err error
					if passphrase != "" {
						signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(keyPem), []byte(passphrase))
					} else {
						signer, err = ssh.ParsePrivateKey([]byte(keyPem))
					}
					if err != nil {
						return nil, fmt.Errorf("sshExec: invalid key: %w", err)
					}
					auths = append(auths, ssh.PublicKeys(signer))
				}
				if pass != "" {
					auths = append(auths, ssh.Password(pass))
				}
				if len(auths) == 0 {
					return nil, fmt.Errorf("sshExec: no auth method provided")
				}

				cfg := &ssh.ClientConfig{
					User:            user,
					Auth:            auths,
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         time.Duration(timeoutMs) * time.Millisecond,
				}
				conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
				if err != nil {
					return nil, fmt.Errorf("sshExec: dial: %w", err)
				}
				defer conn.Close()

				sess, err := conn.NewSession()
				if err != nil {
					return nil, fmt.Errorf("sshExec: session: %w", err)
				}
				defer sess.Close()

				var stdoutBuf, stderrBuf bytes.Buffer
				if cbOut != nil {
					sess.Stdout = io.MultiWriter(&stdoutBuf, callbackWriter{vm: vm, fn: cbOut})
				} else {
					sess.Stdout = &stdoutBuf
				}
				if cbErr != nil {
					sess.Stderr = io.MultiWriter(&stderrBuf, callbackWriter{vm: vm, fn: cbErr})
				} else {
					sess.Stderr = &stderrBuf
				}
				if len(stdinData) > 0 {
					sess.Stdin = bytes.NewReader(stdinData)
				}
				if len(envVars) > 0 {
					for k, v := range envVars {
						_ = sess.Setenv(k, v)
					}
				}

				err = sess.Run(command)
				exitCode := 0
				if err != nil {
					if exitErr, ok := err.(*ssh.ExitError); ok {
						exitCode = exitErr.ExitStatus()
					} else {
						return nil, fmt.Errorf("sshExec: run: %w", err)
					}
				}

				stdoutVal, err := encodeWithEncoding(stdoutBuf.Bytes(), encoding)
				if err != nil {
					return nil, err
				}
				stderrVal, err := encodeWithEncoding(stderrBuf.Bytes(), stderrEncoding)
				if err != nil {
					return nil, err
				}

				return map[string]interface{}{
					"stdout":   stdoutVal,
					"stderr":   stderrVal,
					"exitCode": exitCode,
				}, nil
			})
		})
	} else {
		addHelper("sshExec", "Execute a command over SSH (ssh://user:pass@host:port or opts)", []string{"urlOrHost", "opts"}, func() {
			vm.Set("sshExec", func(urlOrHost string, opts map[string]interface{}) (map[string]interface{}, error) {
				_ = urlOrHost
				_ = opts
				return nil, fmt.Errorf("sshExec is disabled in this build")
			})
		})
	}

	// listDir returns directory entries with optional recursion and filters.
	vm.Set("listDir", func(root string, opts map[string]interface{}) ([]map[string]interface{}, error) {
		if root == "" {
			root = "."
		}
		recursive := false
		maxDepth := maxDirDepth
		var nameRe *regexp.Regexp
		if v, ok := opts["recursive"].(bool); ok {
			recursive = v
		}
		if v, ok := opts["maxDepth"]; ok {
			switch n := v.(type) {
			case int64:
				if n > 0 && int(n) < maxDepth {
					maxDepth = int(n)
				}
			case float64:
				if n > 0 && int(n) < maxDepth {
					maxDepth = int(n)
				}
			}
		}
		if v, ok := opts["nameRegex"].(string); ok && strings.TrimSpace(v) != "" {
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, err
			}
			nameRe = re
		}

		var entries []map[string]interface{}
		rootClean := filepath.Clean(root)
		rootDepth := strings.Count(rootClean, string(os.PathSeparator))
		err := filepath.WalkDir(rootClean, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			depth := strings.Count(p, string(os.PathSeparator)) - rootDepth
			if !recursive && depth > 0 {
				return fs.SkipDir
			}
			if depth > maxDepth {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			name := info.Name()
			if nameRe != nil && !nameRe.MatchString(name) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			entries = append(entries, map[string]interface{}{
				"name":      name,
				"path":      p,
				"isDir":     d.IsDir(),
				"size":      info.Size(),
				"mode":      info.Mode().String(),
				"modTime":   info.ModTime(),
				"truncated": len(entries) >= maxDirEntries,
			})
			if len(entries) >= maxDirEntries {
				return fs.SkipAll
			}
			return nil
		})
		return entries, err
	})

	// fileInfo returns metadata and optional hashes for a path.
	vm.Set("fileInfo", func(path string, opts map[string]interface{}) (map[string]interface{}, error) {
		st, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		withHash := false
		if v, ok := opts["hash"].(bool); ok && v {
			withHash = true
		}
		info := map[string]interface{}{
			"path":    path,
			"isDir":   st.IsDir(),
			"size":    st.Size(),
			"mode":    st.Mode().String(),
			"modTime": st.ModTime(),
		}
		if withHash && !st.IsDir() {
			md5sum, shaSum, hErr := computeFileHashes(path, maxHashBytes)
			if hErr != nil {
				info["hashError"] = hErr.Error()
			} else {
				info["md5"] = md5sum
				info["sha256"] = shaSum
			}
		}
		return info, nil
	})

	// hashFile computes hash for a file (bounded size).
	vm.Set("hashFile", func(path, algo string) (string, error) {
		algo = strings.ToLower(strings.TrimSpace(algo))
		if algo == "" {
			algo = "sha256"
		}
		md5sum, shaSum, err := computeFileHashes(path, maxHashBytes)
		if err != nil {
			return "", err
		}
		switch algo {
		case "md5":
			return md5sum, nil
		case "sha256", "sha":
			return shaSum, nil
		case "sha1":
			h, err := hashFileWith(path, "sha1")
			if err != nil {
				return "", err
			}
			return h, nil
		default:
			return "", fmt.Errorf("unsupported algo: %s", algo)
		}
	})
	vm.Set("hashFileSha1", func(path string) (string, error) {
		return hashFileWith(path, "sha1")
	})

	// hashBuffer hashes a string/bytes using the selected algorithm.
	vm.Set("hashBuffer", func(data interface{}, algo string) (string, error) {
		var b []byte
		switch v := data.(type) {
		case string:
			b = []byte(v)
		case []byte:
			b = v
		default:
			return "", fmt.Errorf("unsupported data type %T", data)
		}
		algo = strings.ToLower(strings.TrimSpace(algo))
		if algo == "" {
			algo = "sha256"
		}
		switch algo {
		case "md5":
			h := md5.Sum(b)
			return hex.EncodeToString(h[:]), nil
		case "sha1":
			h := sha1.Sum(b)
			return hex.EncodeToString(h[:]), nil
		case "sha256", "sha":
			h := sha256.Sum256(b)
			return hex.EncodeToString(h[:]), nil
		default:
			return "", fmt.Errorf("unsupported algo: %s", algo)
		}
	})

	vm.Set("peInfo", func(path string) (map[string]interface{}, error) {
		return peInfo(path)
	})

	// fileStrings extracts printable strings from a file with bounds.
	vm.Set("fileStrings", func(path string, opts map[string]interface{}) ([]string, error) {
		minLen := 4
		limit := maxStringsResults
		if v, ok := opts["minLen"].(int64); ok && v > 1 {
			minLen = int(v)
		} else if v, ok := opts["minLen"].(float64); ok && v > 1 {
			minLen = int(v)
		}
		if v, ok := opts["limit"].(int64); ok && v > 0 && int(v) < limit {
			limit = int(v)
		} else if v, ok := opts["limit"].(float64); ok && v > 0 && int(v) < limit {
			limit = int(v)
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if st.Size() > maxStringsBytes {
			return nil, fmt.Errorf("file too large (%d bytes) for strings", st.Size())
		}

		data, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		re := regexp.MustCompile(fmt.Sprintf("[ -~]{%d,}", minLen))
		matches := re.FindAll(data, limit)
		out := make([]string, 0, len(matches))
		for _, m := range matches {
			out = append(out, string(m))
		}
		return out, nil
	})
	if jsUnsafeFeaturesEnabled {
		addHelper("exec", "Execute a command; returns stdout/stderr/exitCode; optional callbacks and timeout", []string{"cmd", "opts?"}, func() {
			vm.Set("exec", func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) == 0 {
					panic(vm.NewTypeError("exec: command required"))
				}
				cmdStr := call.Argument(0).String()
				opts := map[string]interface{}{}
				if len(call.Arguments) > 1 {
					if o, ok := call.Argument(1).Export().(map[string]interface{}); ok {
						opts = o
					}
				}
				timeoutMs := int64(10000)
				if v, ok := opts["timeoutMs"].(int64); ok && v > 0 {
					timeoutMs = v
				} else if v, ok := opts["timeoutMs"].(float64); ok && v > 0 {
					timeoutMs = int64(v)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
				defer cancel()

				var c *exec.Cmd
				if osType == "windows" {
					c = exec.CommandContext(ctx, "cmd", "/C", cmdStr)
				} else {
					c = exec.CommandContext(ctx, "sh", "-c", cmdStr)
				}

				stdoutBuf := &bytes.Buffer{}
				stderrBuf := &bytes.Buffer{}
				var cbOut, cbErr goja.Callable
				if v, ok := opts["stdoutCallback"]; ok {
					if fn, ok := goja.AssertFunction(vm.ToValue(v)); ok {
						cbOut = fn
					}
				}
				if v, ok := opts["stderrCallback"]; ok {
					if fn, ok := goja.AssertFunction(vm.ToValue(v)); ok {
						cbErr = fn
					}
				}
				if cbOut != nil {
					c.Stdout = io.MultiWriter(stdoutBuf, callbackWriter{vm: vm, fn: cbOut})
				} else {
					c.Stdout = stdoutBuf
				}
				if cbErr != nil {
					c.Stderr = io.MultiWriter(stderrBuf, callbackWriter{vm: vm, fn: cbErr})
				} else {
					c.Stderr = stderrBuf
				}

				err := c.Run()
				exitCode := 0
				if err != nil {
					if ee, ok := err.(*exec.ExitError); ok {
						if ws, ok := ee.Sys().(interface{ ExitStatus() int }); ok {
							exitCode = ws.ExitStatus()
						}
					}
				} else if c.ProcessState != nil {
					exitCode = c.ProcessState.ExitCode()
				}

				res := map[string]interface{}{
					"stdout":   stdoutBuf.String(),
					"stderr":   stderrBuf.String(),
					"exitCode": exitCode,
				}
				if err != nil {
					res["error"] = err.Error()
				}
				return vm.ToValue(res)
			})
		})
	} else {
		addHelper("exec", "Execute a command; returns stdout/stderr/exitCode; optional callbacks and timeout", []string{"cmd", "opts?"}, func() {
			vm.Set("exec", func(call goja.FunctionCall) goja.Value {
				return vm.ToValue(map[string]interface{}{
					"error": "exec is disabled in this build",
				})
			})
		})
	}
	addHelper("log", "Print arguments to stdout (also returned from JS run)", []string{"...args"}, func() {
		vm.Set("log", func(args ...interface{}) {
			log.Println(args...)
		})
	})
	addHelper("reportProgress", "Report a progress payload back to the host (in-memory + optional MQTT progress_to)", []string{"payload"}, func() {
		vm.Set("reportProgress", func(payload interface{}) {
			if progress == nil {
				return
			}
			cpuPct, memBytes := currentTelemetry()
			entry := map[string]interface{}{
				"ts":             time.Now().UTC().Format(time.RFC3339Nano),
				"payload":        payload,
				"agent":          agentName,
				"manager":        managerName,
				"correlation_id": correlationID,
				"memBytes":       memBytes,
				"cpuPct":         cpuPct,
			}
			*progress = append(*progress, entry)
			if len(*progress) > maxListEntries {
				*progress = (*progress)[len(*progress)-maxListEntries:]
			}
			if mqttClient != nil && progressTopic != "" {
				if b, err := json.Marshal(entry); err == nil {
					token := mqttClient.Publish(progressTopic, 1, false, b)
					token.Wait()
				}
			}
		})
	})
	addHelper("progressStdout", "Convenience: emit stdout chunk to progress_to (base64 in data)", []string{"chunk"}, func() {
		vm.Set("progressStdout", func(chunk string) {
			if chunk == "" {
				return
			}
			vm.Get("reportProgress").Export().(func(interface{}))(map[string]interface{}{
				"type": "stdout",
				"data": base64.StdEncoding.EncodeToString([]byte(chunk)),
			})
		})
	})
	addHelper("outputDebugString", "Send a debug string to the host (logs or MQTT debug_to)", []string{"msg"}, func() {
		vm.Set("outputDebugString", func(msg string) {
			if debugTopic != "" && mqttClient != nil {
				token := mqttClient.Publish(debugTopic, 0, false, msg)
				token.Wait()
			} else {
				log.Println(msg)
			}
		})
	})
	vm.Set("env", func(name string) string {
		return os.Getenv(name)
	})
	addHelper("agentInfo", "Return host OS, hostname, and CLI version", []string{}, func() {
		vm.Set("agentInfo", func() map[string]interface{} {
			hn, _ := os.Hostname()
			return map[string]interface{}{
				"os":       runtime.GOOS,
				"hostname": hn,
				"version":  version.Version,
			}
		})
	})
	vm.Set("base64Encode", func(data string) string {
		return base64.StdEncoding.EncodeToString([]byte(data))
	})
	vm.Set("base64Decode", func(data string) (string, error) {
		decoded, err := base64.StdEncoding.DecodeString(data)
		return string(decoded), err
	})
	vm.Set("hexEncode", func(data string) string {
		return hex.EncodeToString([]byte(data))
	})
	vm.Set("hexDecode", func(data string) (string, error) {
		b, err := hex.DecodeString(strings.TrimSpace(data))
		return string(b), err
	})
	vm.Set("urlEncode", func(data string) string {
		return url.QueryEscape(data)
	})
	vm.Set("urlDecode", func(data string) (string, error) {
		return url.QueryUnescape(data)
	})
	vm.Set("xmlParse", func(xmlStr string) (map[string]interface{}, error) {
		var generic interface{}
		if err := xml.Unmarshal([]byte(xmlStr), &generic); err != nil {
			return nil, err
		}
		if m, ok := generic.(map[string]interface{}); ok {
			return m, nil
		}
		return map[string]interface{}{"value": generic}, nil
	})
	vm.Set("xmlEncode", func(obj interface{}) (string, error) {
		b, err := xml.Marshal(obj)
		return string(b), err
	})
	addHelper("iniParse", "Parse INI string into object", []string{"iniStr"}, func() {
		vm.Set("iniParse", func(iniStr string) (map[string]interface{}, error) {
			cfg, err := ini.Load([]byte(iniStr))
			if err != nil {
				return nil, err
			}
			out := map[string]interface{}{}
			for _, sec := range cfg.Sections() {
				secMap := map[string]interface{}{}
				for _, k := range sec.Keys() {
					secMap[k.Name()] = k.Value()
				}
				out[sec.Name()] = secMap
			}
			return out, nil
		})
	})
	addHelper("iniEncode", "Encode object into INI string", []string{"obj"}, func() {
		vm.Set("iniEncode", func(obj map[string]map[string]interface{}) (string, error) {
			cfg := ini.Empty()
			for secName, kv := range obj {
				sec, err := cfg.NewSection(secName)
				if err != nil {
					return "", err
				}
				for k, v := range kv {
					sec.NewKey(k, fmt.Sprint(v))
				}
			}
			var buf bytes.Buffer
			_, err := cfg.WriteTo(&buf)
			return buf.String(), err
		})
	})
	addHelper("yamlParse", "Parse YAML string into object", []string{"yamlStr"}, func() {
		vm.Set("yamlParse", func(yamlStr string) (map[string]interface{}, error) {
			var out map[string]interface{}
			if err := yaml.Unmarshal([]byte(yamlStr), &out); err != nil {
				return nil, err
			}
			return out, nil
		})
	})
	addHelper("yamlEncode", "Encode object into YAML string", []string{"obj"}, func() {
		vm.Set("yamlEncode", func(obj interface{}) (string, error) {
			b, err := yaml.Marshal(obj)
			return string(b), err
		})
	})
	addHelper("tomlParse", "Parse TOML string into object", []string{"tomlStr"}, func() {
		vm.Set("tomlParse", func(tomlStr string) (map[string]interface{}, error) {
			var out map[string]interface{}
			if err := toml.Unmarshal([]byte(tomlStr), &out); err != nil {
				return nil, err
			}
			return out, nil
		})
	})
	addHelper("tomlEncode", "Encode object into TOML string", []string{"obj"}, func() {
		vm.Set("tomlEncode", func(obj interface{}) (string, error) {
			b, err := toml.Marshal(obj)
			return string(b), err
		})
	})
	vm.Set("gzipCompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
		b, err := toBytesWithEncoding(data, "")
		if err != nil {
			return nil, fmt.Errorf("gzipCompress: %w", err)
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(b); err != nil {
			return nil, err
		}
		if err := gz.Close(); err != nil {
			return nil, err
		}
		outEnc := "buffer"
		if len(encodingOpt) > 0 {
			outEnc = strings.ToLower(strings.TrimSpace(encodingOpt[0]))
		}
		return encodeWithEncoding(buf.Bytes(), outEnc)
	})
	vm.Set("gzipDecompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
		// Optional encodings: input encoding (default base64 for strings, buffer for binary) and output encoding (default buffer).
		inEnc := ""
		outEnc := "buffer"
		if len(encodingOpt) > 0 {
			inEnc = strings.ToLower(strings.TrimSpace(encodingOpt[0]))
		}
		if len(encodingOpt) > 1 {
			outEnc = strings.ToLower(strings.TrimSpace(encodingOpt[1]))
		}

		stringInEnc := inEnc
		if stringInEnc == "" {
			stringInEnc = "base64"
		}
		raw, err := toBytesWithEncoding(data, stringInEnc)
		if err != nil {
			return nil, fmt.Errorf("gzipDecompress: %w", err)
		}

		r, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		outBytes, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		return encodeWithEncoding(outBytes, outEnc)
	})

	addHelper("deflateCompress", "Compress with zlib/deflate (Node-like deflate)", []string{"data", "outputEncoding?"}, func() {
		vm.Set("deflateCompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			b, err := toBytesWithEncoding(data, "")
			if err != nil {
				return nil, fmt.Errorf("deflateCompress: %w", err)
			}
			var buf bytes.Buffer
			w := zlib.NewWriter(&buf)
			if _, err := w.Write(b); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			outEnc := "buffer"
			if len(encodingOpt) > 0 {
				outEnc = encodingOpt[0]
			}
			return encodeWithEncoding(buf.Bytes(), outEnc)
		})
	})
	addHelper("deflateDecompress", "Decompress zlib/deflate", []string{"data", "inputEncoding?", "outputEncoding?"}, func() {
		vm.Set("deflateDecompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			inEnc := ""
			if len(encodingOpt) > 0 {
				inEnc = encodingOpt[0]
			}
			outEnc := "buffer"
			if len(encodingOpt) > 1 {
				outEnc = encodingOpt[1]
			}
			raw, err := toBytesWithEncoding(data, inEnc)
			if err != nil {
				return nil, fmt.Errorf("deflateDecompress: %w", err)
			}
			r, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				return nil, err
			}
			defer r.Close()
			outBytes, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			return encodeWithEncoding(outBytes, outEnc)
		})
	})

	addHelper("brotliCompress", "Compress with Brotli", []string{"data", "outputEncoding?"}, func() {
		vm.Set("brotliCompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			b, err := toBytesWithEncoding(data, "")
			if err != nil {
				return nil, fmt.Errorf("brotliCompress: %w", err)
			}
			var buf bytes.Buffer
			w := brotli.NewWriterLevel(&buf, brotli.DefaultCompression)
			if _, err := w.Write(b); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			outEnc := "buffer"
			if len(encodingOpt) > 0 {
				outEnc = encodingOpt[0]
			}
			return encodeWithEncoding(buf.Bytes(), outEnc)
		})
	})
	addHelper("brotliDecompress", "Decompress Brotli", []string{"data", "inputEncoding?", "outputEncoding?"}, func() {
		vm.Set("brotliDecompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			inEnc := ""
			if len(encodingOpt) > 0 {
				inEnc = encodingOpt[0]
			}
			outEnc := "buffer"
			if len(encodingOpt) > 1 {
				outEnc = encodingOpt[1]
			}
			raw, err := toBytesWithEncoding(data, inEnc)
			if err != nil {
				return nil, fmt.Errorf("brotliDecompress: %w", err)
			}
			r := brotli.NewReader(bytes.NewReader(raw))
			outBytes, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			return encodeWithEncoding(outBytes, outEnc)
		})
	})

	addHelper("zstdCompress", "Compress with Zstandard", []string{"data", "outputEncoding?"}, func() {
		vm.Set("zstdCompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			b, err := toBytesWithEncoding(data, "")
			if err != nil {
				return nil, fmt.Errorf("zstdCompress: %w", err)
			}
			enc, err := zstd.NewWriter(nil)
			if err != nil {
				return nil, err
			}
			out := enc.EncodeAll(b, nil)
			enc.Close()
			outEnc := "buffer"
			if len(encodingOpt) > 0 {
				outEnc = encodingOpt[0]
			}
			return encodeWithEncoding(out, outEnc)
		})
	})
	addHelper("zstdDecompress", "Decompress Zstandard", []string{"data", "inputEncoding?", "outputEncoding?"}, func() {
		vm.Set("zstdDecompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			inEnc := ""
			if len(encodingOpt) > 0 {
				inEnc = encodingOpt[0]
			}
			outEnc := "buffer"
			if len(encodingOpt) > 1 {
				outEnc = encodingOpt[1]
			}
			raw, err := toBytesWithEncoding(data, inEnc)
			if err != nil {
				return nil, fmt.Errorf("zstdDecompress: %w", err)
			}
			dec, err := zstd.NewReader(nil)
			if err != nil {
				return nil, err
			}
			defer dec.Close()
			out, err := dec.DecodeAll(raw, nil)
			if err != nil {
				return nil, err
			}
			return encodeWithEncoding(out, outEnc)
		})
	})

	addHelper("lz4Compress", "Compress with LZ4", []string{"data", "outputEncoding?"}, func() {
		vm.Set("lz4Compress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			b, err := toBytesWithEncoding(data, "")
			if err != nil {
				return nil, fmt.Errorf("lz4Compress: %w", err)
			}
			var buf bytes.Buffer
			w := lz4.NewWriter(&buf)
			if _, err := w.Write(b); err != nil {
				return nil, err
			}
			if err := w.Close(); err != nil {
				return nil, err
			}
			outEnc := "buffer"
			if len(encodingOpt) > 0 {
				outEnc = encodingOpt[0]
			}
			return encodeWithEncoding(buf.Bytes(), outEnc)
		})
	})
	addHelper("lz4Decompress", "Decompress LZ4", []string{"data", "inputEncoding?", "outputEncoding?"}, func() {
		vm.Set("lz4Decompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			inEnc := ""
			if len(encodingOpt) > 0 {
				inEnc = encodingOpt[0]
			}
			outEnc := "buffer"
			if len(encodingOpt) > 1 {
				outEnc = encodingOpt[1]
			}
			raw, err := toBytesWithEncoding(data, inEnc)
			if err != nil {
				return nil, fmt.Errorf("lz4Decompress: %w", err)
			}
			r := lz4.NewReader(bytes.NewReader(raw))
			outBytes, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			return encodeWithEncoding(outBytes, outEnc)
		})
	})

	addHelper("snappyCompress", "Compress with Snappy", []string{"data", "outputEncoding?"}, func() {
		vm.Set("snappyCompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			b, err := toBytesWithEncoding(data, "")
			if err != nil {
				return nil, fmt.Errorf("snappyCompress: %w", err)
			}
			out := snappy.Encode(nil, b)
			outEnc := "buffer"
			if len(encodingOpt) > 0 {
				outEnc = encodingOpt[0]
			}
			return encodeWithEncoding(out, outEnc)
		})
	})
	addHelper("snappyDecompress", "Decompress Snappy", []string{"data", "inputEncoding?", "outputEncoding?"}, func() {
		vm.Set("snappyDecompress", func(data goja.Value, encodingOpt ...string) (interface{}, error) {
			inEnc := ""
			if len(encodingOpt) > 0 {
				inEnc = encodingOpt[0]
			}
			outEnc := "buffer"
			if len(encodingOpt) > 1 {
				outEnc = encodingOpt[1]
			}
			raw, err := toBytesWithEncoding(data, inEnc)
			if err != nil {
				return nil, fmt.Errorf("snappyDecompress: %w", err)
			}
			out, err := snappy.Decode(nil, raw)
			if err != nil {
				return nil, err
			}
			return encodeWithEncoding(out, outEnc)
		})
	})
	vm.Set("uuidv4", func() (string, error) {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		b[6] = (b[6] & 0x0f) | 0x40
		b[8] = (b[8] & 0x3f) | 0x80
		return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
			b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
	})
	vm.Set("randString", func(n int) (string, error) {
		if n <= 0 || n > 1024 {
			return "", fmt.Errorf("length must be 1-1024")
		}
		out := make([]byte, n)
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for i := 0; i < n; i++ {
			out[i] = randAlphabet[int(buf[i])%len(randAlphabet)]
		}
		return string(out), nil
	})
	vm.Set("entropy", func(data string) float64 {
		if data == "" {
			return 0
		}
		counts := make(map[rune]int)
		for _, r := range data {
			counts[r]++
		}
		var ent float64
		n := float64(len(data))
		for _, c := range counts {
			p := float64(c) / n
			ent -= p * (math.Log2(p))
		}
		return ent
	})
	vm.Set("fileEntropy", func(path string, maxBytes int) (float64, error) {
		if maxBytes <= 0 || maxBytes > maxEntropyFileRead {
			maxBytes = maxEntropyFileRead
		}
		f, err := os.Open(path)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		buf := make([]byte, maxBytes)
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return 0, err
		}
		return computeEntropy(buf[:n]), nil
	})
	vm.Set("isPrivateIp", func(ipStr string) bool {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			return false
		}
		privateBlocks := []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
			"169.254.0.0/16",
			"fc00::/7", "::1/128",
		}
		for _, cidr := range privateBlocks {
			_, block, _ := net.ParseCIDR(cidr)
			if block.Contains(ip) {
				return true
			}
		}
		return false
	})
	vm.Set("domainEntropy", func(domain string) float64 {
		return computeEntropy([]byte(domain))
	})
	vm.Set("tld", func(domain string) string {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			return ""
		}
		parts := strings.Split(domain, ".")
		if len(parts) < 2 {
			return domain
		}
		return parts[len(parts)-1]
	})
	vm.Set("multiPortCheck", func(host string, ports []interface{}, timeoutMs int) ([]map[string]interface{}, error) {
		if !jsNetworkProbesEnabled {
			return nil, fmt.Errorf("multiPortCheck is disabled in this build")
		}
		if len(ports) > maxPortsChecked {
			ports = ports[:maxPortsChecked]
		}
		timeout := time.Duration(timeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		var results []map[string]interface{}
		for _, p := range ports {
			var port int
			switch v := p.(type) {
			case int64:
				port = int(v)
			case float64:
				port = int(v)
			default:
				continue
			}
			open := false
			addr := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				open = true
				conn.Close()
			}
			results = append(results, map[string]interface{}{"port": port, "open": open})
		}
		return results, nil
	})
	vm.Set("httpFingerprint", func(u string, opts map[string]interface{}) (map[string]interface{}, error) {
		if !jsNetworkProbesEnabled {
			return nil, fmt.Errorf("httpFingerprint is disabled in this build")
		}
		bodyLimit := maxHTTPBody
		if v, ok := opts["bodyLimit"].(int64); ok && v > 0 && int(v) < bodyLimit {
			bodyLimit = int(v)
		} else if v, ok := opts["bodyLimit"].(float64); ok && v > 0 && int(v) < bodyLimit {
			bodyLimit = int(v)
		}
		return httpFingerprintInternal(u, bodyLimit)
	})
	vm.Set("tlsFingerprint", func(host string, port int, timeoutMs int) (map[string]interface{}, error) {
		if !jsNetworkProbesEnabled {
			return nil, fmt.Errorf("tlsFingerprint is disabled in this build")
		}
		return tlsFingerprintInternal(host, port, timeoutMs)
	})
	vm.Set("whoisSummary", func(target string) (map[string]interface{}, error) {
		if !jsNetworkProbesEnabled {
			return nil, fmt.Errorf("whoisSummary is disabled in this build")
		}
		return whoisSummary(target)
	})
	vm.Set("dnsTrace", func(name string) ([]map[string]interface{}, error) {
		if !jsNetworkProbesEnabled {
			return nil, fmt.Errorf("dnsTrace is disabled in this build")
		}
		return dnsTrace(name)
	})
	vm.Set("ja3", func(host string, port int) (string, error) {
		if !jsNetworkProbesEnabled {
			return "", fmt.Errorf("ja3 is disabled in this build")
		}
		return computeJA3(host, port)
	})
	addHelper("listServices", "List OS services (bounded best-effort)", []string{}, func() {
		vm.Set("listServices", func() ([]map[string]interface{}, error) {
			switch osType {
			case "linux", "darwin":
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--all", "--no-page", "--no-legend", "--property=Id,LoadState,ActiveState,SubState,Description")
				out, err := cmd.Output()
				if err != nil {
					return nil, err
				}
				return parseSystemctlShow(out, maxListEntries), nil
			case "windows":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "sc", "query", "type=", "service", "state=", "all")
				out, err := cmd.Output()
				if err != nil {
					return nil, err
				}
				return parseScQuery(out, maxListEntries), nil
			default:
				return nil, fmt.Errorf("unsupported OS: %s", osType)
			}
		})
	})
	addHelper("listServiceDetails", "List services with path/hash/signature where available", []string{}, func() {
		vm.Set("listServiceDetails", func() ([]map[string]interface{}, error) {
			switch osType {
			case "linux":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--all", "--no-page", "--no-legend", "--property=Id,LoadState,ActiveState,SubState,Description,FragmentPath,ExecStart")
				out, err := cmd.Output()
				if err != nil {
					return nil, err
				}
				entries := parseSystemctlDetails(string(out), maxListEntries)
				hashed := 0
				for _, e := range entries {
					if hashed >= maxServiceHashes {
						break
					}
					if path, ok := e["path"].(string); ok && path != "" {
						if _, err := os.Stat(path); err == nil {
							if _, sha, hErr := computeFileHashes(path, maxServiceHashSize); hErr == nil {
								e["hash"] = sha
								hashed++
							}
						}
					}
				}
				return entries, nil
			case "windows":
				return helperWindowsServiceDetails(maxListEntries, maxServiceHashSize)
			case "darwin":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, "launchctl", "list").Output()
				if err != nil {
					return nil, err
				}
				lines := strings.Split(string(out), "\n")
				var res []map[string]interface{}
				for _, l := range lines {
					fields := strings.Fields(l)
					if len(fields) != 3 || fields[0] == "PID" {
						continue
					}
					label := fields[2]
					entry := map[string]interface{}{"label": label, "pid": fields[0], "status": fields[1]}
					plistPaths := []string{
						filepath.Join("/Library/LaunchDaemons", label+".plist"),
						filepath.Join("/System/Library/LaunchDaemons", label+".plist"),
						filepath.Join("/Library/LaunchAgents", label+".plist"),
						filepath.Join("/System/Library/LaunchAgents", label+".plist"),
					}
					for _, pp := range plistPaths {
						if _, err := os.Stat(pp); err == nil {
							entry["plist"] = pp
							data, _ := os.ReadFile(pp)
							if bytes.Contains(data, []byte("<string>/")) {
								idx := bytes.Index(data, []byte("<string>/"))
								end := bytes.Index(data[idx:], []byte("</string>"))
								if end > 0 {
									path := string(data[idx+len("<string>") : idx+end])
									entry["path"] = path
									if _, err := os.Stat(path); err == nil {
										if _, sha, hErr := computeFileHashes(path, maxServiceHashSize); hErr == nil {
											entry["hash"] = sha
										}
									}
								}
							}
							break
						}
					}
					res = append(res, entry)
					if len(res) >= maxListEntries {
						break
					}
				}
				return res, nil
			default:
				return nil, fmt.Errorf("unsupported OS: %s", osType)
			}
		})
	})
	vm.Set("listServiceDetails", func() ([]map[string]interface{}, error) {
		switch osType {
		case "linux":
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "systemctl", "show", "--type=service", "--all", "--no-page", "--no-legend", "--property=Id,LoadState,ActiveState,SubState,Description,FragmentPath,ExecStart")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			entries := parseSystemctlDetails(string(out), maxListEntries)
			hashed := 0
			for _, e := range entries {
				if hashed >= maxServiceHashes {
					break
				}
				if path, ok := e["path"].(string); ok && path != "" {
					if _, err := os.Stat(path); err == nil {
						if _, sha, hErr := computeFileHashes(path, maxServiceHashSize); hErr == nil {
							e["hash"] = sha
							hashed++
						}
					}
				}
			}
			return entries, nil
		case "windows":
			return helperWindowsServiceDetails(maxListEntries, maxServiceHashSize)
		case "darwin":
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "launchctl", "list").Output()
			if err != nil {
				return nil, err
			}
			lines := strings.Split(string(out), "\n")
			var res []map[string]interface{}
			for _, l := range lines {
				fields := strings.Fields(l)
				if len(fields) != 3 || fields[0] == "PID" {
					continue
				}
				label := fields[2]
				entry := map[string]interface{}{"label": label, "pid": fields[0], "status": fields[1]}
				plistPaths := []string{
					filepath.Join("/Library/LaunchDaemons", label+".plist"),
					filepath.Join("/System/Library/LaunchDaemons", label+".plist"),
					filepath.Join("/Library/LaunchAgents", label+".plist"),
					filepath.Join("/System/Library/LaunchAgents", label+".plist"),
				}
				for _, pp := range plistPaths {
					if _, err := os.Stat(pp); err == nil {
						entry["plist"] = pp
						data, _ := os.ReadFile(pp)
						if bytes.Contains(data, []byte("<string>/")) {
							idx := bytes.Index(data, []byte("<string>/"))
							end := bytes.Index(data[idx:], []byte("</string>"))
							if end > 0 {
								path := string(data[idx+len("<string>") : idx+end])
								entry["path"] = path
								if _, err := os.Stat(path); err == nil {
									if _, sha, hErr := computeFileHashes(path, maxServiceHashSize); hErr == nil {
										entry["hash"] = sha
									}
								}
							}
						}
						break
					}
				}
				res = append(res, entry)
				if len(res) >= maxListEntries {
					break
				}
			}
			return res, nil
		default:
			return nil, fmt.Errorf("unsupported OS: %s", osType)
		}
	})
	vm.Set("listAutoruns", func() ([]map[string]interface{}, error) {
		var res []map[string]interface{}
		switch osType {
		case "linux", "darwin":
			paths := []string{
				filepath.Join(os.Getenv("HOME"), ".config", "autostart"),
				"/etc/xdg/autostart",
				filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents"),
				"/Library/LaunchAgents",
				"/Library/LaunchDaemons",
			}
			for _, p := range paths {
				entries, _ := os.ReadDir(p)
				for _, e := range entries {
					entry := map[string]interface{}{
						"path": p,
						"name": e.Name(),
						"type": "autostart",
					}
					res = append(res, entry)
					if len(res) >= maxListEntries {
						return res, nil
					}
				}
			}
		case "windows":
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			res = parseWindowsAutorunReg(ctx, maxListEntries)
		default:
			return nil, fmt.Errorf("unsupported OS: %s", osType)
		}
		return res, nil
	})
	vm.Set("listScheduledTasks", func() ([]map[string]interface{}, error) {
		var res []map[string]interface{}
		switch osType {
		case "linux":
			if data, err := os.ReadFile("/etc/crontab"); err == nil {
				res = append(res, parseCronLines(strings.Split(string(data), "\n"), true, "/etc/crontab", maxListEntries-len(res))...)
			}
			if len(res) >= maxListEntries {
				return res, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "crontab", "-l").Output(); err == nil {
				res = append(res, parseCronLines(strings.Split(string(out), "\n"), false, "crontab", maxListEntries-len(res))...)
			}
		case "darwin":
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if out, err := exec.CommandContext(ctx, "launchctl", "list").Output(); err == nil {
				res = append(res, parseLaunchctlList(string(out), maxListEntries-len(res))...)
			}
		case "windows":
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "powershell", "-NoLogo", "-NonInteractive", "-Command", "Get-ScheduledTask | Select-Object TaskName,State,LastRunTime,NextRunTime | ConvertTo-Json")
			out, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			dec := json.NewDecoder(strings.NewReader(string(out)))
			dec.UseNumber()
			if err := dec.Decode(&res); err != nil {
				return nil, err
			}
			if len(res) > maxListEntries {
				res = res[:maxListEntries]
			}
		default:
			return nil, fmt.Errorf("unsupported OS: %s", osType)
		}
		return res, nil
	})
	vm.Set("authFailures", func() (map[string]interface{}, error) {
		if !jsSensitiveReadsEnabled {
			return nil, fmt.Errorf("authFailures is disabled in this build")
		}
		switch osType {
		case "linux", "darwin":
			paths := []string{"/var/log/auth.log", "/var/log/secure"}
			var lines []string
			for _, p := range paths {
				data, err := os.ReadFile(p)
				if err != nil {
					continue
				}
				lines = strings.Split(string(data), "\n")
				break
			}
			if len(lines) == 0 {
				return map[string]interface{}{"count": 0, "entries": []map[string]interface{}{}}, nil
			}
			entries := parseAuthFailures(lines, maxAuthLines)
			return map[string]interface{}{"count": len(entries), "entries": entries}, nil
		case "windows":
			return nil, fmt.Errorf("authFailures not implemented for windows")
		default:
			return nil, fmt.Errorf("unsupported OS: %s", osType)
		}
	})
	vm.Set("regListValues", func(key string) ([]map[string]interface{}, error) {
		if !jsSensitiveReadsEnabled {
			return nil, fmt.Errorf("regListValues is disabled in this build")
		}
		if osType != "windows" {
			return nil, fmt.Errorf("regListValues: unsupported OS %s", osType)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "reg", "query", key)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return parseRegQueryValues(string(out), maxRegEntries), nil
	})
	vm.Set("regListSubkeys", func(key string) ([]string, error) {
		if !jsSensitiveReadsEnabled {
			return nil, fmt.Errorf("regListSubkeys is disabled in this build")
		}
		if osType != "windows" {
			return nil, fmt.Errorf("regListSubkeys: unsupported OS %s", osType)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "reg", "query", key)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return parseRegSubkeys(string(out), key, maxRegEntries), nil
	})
	vm.Set("regGet", func(key, value string) (map[string]interface{}, error) {
		if !jsSensitiveReadsEnabled {
			return nil, fmt.Errorf("regGet is disabled in this build")
		}
		if osType != "windows" {
			return nil, fmt.Errorf("regGet: unsupported OS %s", osType)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "reg", "query", key, "/v", value)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		values := parseRegQueryValues(string(out), 1)
		if len(values) == 0 {
			return nil, fmt.Errorf("value not found")
		}
		return values[0], nil
	})
	vm.Set("sleep", func(ms int) *goja.Promise {
		p, resolve, _ := vm.NewPromise()
		time.AfterFunc(time.Duration(ms)*time.Millisecond, func() {
			resolve(goja.Undefined())
		})
		return p
	})

	// file hash with 60s cache or on size/mtime change
	vm.Set("getFileMd5", func(path string) (string, error) {
		info, err := os.Stat(path)
		if err != nil {
			return "", err
		}
		now := time.Now()
		hashCacheMu.Lock()
		entry, ok := hashCache[path]
		if ok && now.Sub(entry.last) < 60*time.Second && entry.mtime.Equal(info.ModTime()) && entry.size == info.Size() {
			md5sum := entry.md5sum
			hashCacheMu.Unlock()
			return md5sum, nil
		}
		hashCacheMu.Unlock()
		// compute hashes
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		h := md5.New()
		h2 := sha256.New()
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				h.Write(buf[:n])
				h2.Write(buf[:n])
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return "", err
			}
		}
		md5sum := hex.EncodeToString(h.Sum(nil))
		shaSum := hex.EncodeToString(h2.Sum(nil))
		// cache entry
		hashCacheMu.Lock()
		hashCache[path] = &hashCacheEntry{mtime: info.ModTime(), size: info.Size(), md5sum: md5sum, sha256: shaSum, last: now}
		hashCacheMu.Unlock()
		return md5sum, nil
	})
	vm.Set("getFileSha256", func(path string) (string, error) {
		// reuse MD5 loader to populate cache
		if _, err := vm.Get("getFileMd5").Export().(func(string) (string, error))(path); err != nil {
			return "", err
		}
		hashCacheMu.Lock()
		e := hashCache[path]
		hashCacheMu.Unlock()
		if e == nil {
			return "", errors.New("cache missing entry")
		}
		return e.sha256, nil
	})

	// directory walker
	addHelper("walkDir", "Walk directory tree and invoke callback for each entry", []string{"root", "cb"}, func() {
		vm.Set("walkDir", func(root string, cb func(string, map[string]interface{})) error {
			if !jsWalkDirEnabled {
				return fmt.Errorf("walkDir is disabled in this build")
			}
			return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				info, err := d.Info()
				if err != nil {
					return err
				}
				cb(p, map[string]interface{}{"isDir": d.IsDir(), "size": info.Size(), "modTime": info.ModTime(), "mode": info.Mode().String()})
				return nil
			})
		})
	})

	// hostsFileListEntries parses the local hosts file and returns entries.
	addHelper("hostsFileListEntries", "Parse local hosts file and return entries (ip, hostnames, comment)", []string{}, func() {
		vm.Set("hostsFileListEntries", func() ([]map[string]interface{}, error) {
			if !jsSensitiveReadsEnabled {
				return nil, fmt.Errorf("hostsFileListEntries is disabled in this build")
			}
			hostsPath := "/etc/hosts"
			if runtime.GOOS == "windows" {
				hostsPath = `C:\Windows\System32\drivers\etc\hosts`
			}
			data, err := os.ReadFile(hostsPath)
			if err != nil {
				return nil, err
			}
			return parseHostsContent(string(data), maxListEntries), nil
		})
	})

	// dnsLookup resolves a hostname to IPs.
	addHelper("dnsLookup", "Resolve a hostname to IPs", []string{"name"}, func() {
		vm.Set("dnsLookup", func(name string) ([]string, error) {
			if !jsNetworkProbesEnabled {
				return nil, fmt.Errorf("dnsLookup is disabled in this build")
			}
			ips, err := net.LookupHost(name)
			if err != nil {
				return nil, err
			}
			return ips, nil
		})
	})

	// reverseDNS performs a PTR lookup for an IP.
	addHelper("reverseDNS", "Reverse lookup an IP to hostnames", []string{"ip"}, func() {
		vm.Set("reverseDNS", func(ip string) ([]string, error) {
			if !jsNetworkProbesEnabled {
				return nil, fmt.Errorf("reverseDNS is disabled in this build")
			}
			ptrs, err := net.LookupAddr(ip)
			if err != nil {
				return nil, err
			}
			return ptrs, nil
		})
	})
	addHelper("dnsCache", "List DNS cache entries (best-effort per OS)", []string{}, func() {
		vm.Set("dnsCache", func() ([]map[string]interface{}, error) {
			switch runtime.GOOS {
			case "windows":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, "ipconfig", "/displaydns").CombinedOutput()
				if err != nil {
					return nil, err
				}
				return parseWindowsDnsCache(string(out), maxListEntries), nil
			case "darwin":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, "dscacheutil", "-cachedump", "-entries", "host").CombinedOutput()
				if err != nil {
					return nil, err
				}
				return parseDscacheutilHosts(string(out), maxListEntries), nil
			case "linux":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, "nscd", "-g").CombinedOutput()
				if err != nil {
					// fallback: not available
					return nil, fmt.Errorf("dns cache not available")
				}
				return parseNscdHosts(string(out), maxListEntries), nil
			default:
				return nil, fmt.Errorf("dns cache not implemented for %s", runtime.GOOS)
			}
		})
	})

	// tcpIsOpen checks TCP reachability.
	addHelper("tcpIsOpen", "Check if TCP port is open (bounded timeout)", []string{"host", "port", "timeoutMs"}, func() {
		vm.Set("tcpIsOpen", func(host string, port int, timeoutMs int) map[string]interface{} {
			if !jsNetworkProbesEnabled {
				return map[string]interface{}{"open": false, "error": "tcpIsOpen is disabled in this build"}
			}
			res := map[string]interface{}{"open": false}
			timeout := time.Duration(timeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 2 * time.Second
			}
			addr := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				res["error"] = err.Error()
				return res
			}
			res["open"] = true
			conn.Close()
			return res
		})
	})

	// udpIsOpen is best-effort: send empty packet and wait for error/timeout.
	vm.Set("udpIsOpen", func(host string, port int, timeoutMs int) map[string]interface{} {
		if !jsNetworkProbesEnabled {
			return map[string]interface{}{"open": false, "error": "udpIsOpen is disabled in this build"}
		}
		res := map[string]interface{}{"open": false}
		timeout := time.Duration(timeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("udp", addr, timeout)
		if err != nil {
			res["error"] = err.Error()
			return res
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write([]byte{0})
		buf := make([]byte, 1)
		_, err = conn.Read(buf)
		// For UDP, lack of ICMP errors may just time out; treat timeout as inconclusive open.
		if err == nil {
			res["open"] = true
			return res
		}
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			res["open"] = true
			return res
		}
		res["error"] = err.Error()
		return res
	})

	// tcpBanner grabs a small banner from TCP.
	vm.Set("tcpBanner", func(host string, port int, timeoutMs int) map[string]interface{} {
		if !jsNetworkProbesEnabled {
			return map[string]interface{}{"error": "tcpBanner is disabled in this build"}
		}
		res := map[string]interface{}{}
		timeout := time.Duration(timeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			res["error"] = err.Error()
			return res
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			res["error"] = err.Error()
		}
		res["banner"] = string(buf[:n])
		return res
	})

	// tlsBanner returns TLS peer cert info and optional banner (pre-application data).
	vm.Set("tlsBanner", func(host string, port int, timeoutMs int) map[string]interface{} {
		if !jsNetworkProbesEnabled {
			return map[string]interface{}{"error": "tlsBanner is disabled in this build"}
		}
		res := map[string]interface{}{}
		timeout := time.Duration(timeoutMs) * time.Millisecond
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		addr := fmt.Sprintf("%s:%d", host, port)
		d := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err != nil {
			res["error"] = err.Error()
			return res
		}
		defer conn.Close()
		state := conn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			c := state.PeerCertificates[0]
			res["cert"] = map[string]interface{}{
				"subject":    c.Subject.String(),
				"issuer":     c.Issuer.String(),
				"notBefore":  c.NotBefore,
				"notAfter":   c.NotAfter,
				"dnsNames":   c.DNSNames,
				"commonName": c.Subject.CommonName,
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err == nil || err == io.EOF {
			res["banner"] = string(buf[:n])
		}
		return res
	})

	// process walker: enumerate all system processes using gopsutil
	vm.Set("walkProcesses", func(cb func(map[string]interface{})) error {
		procs, err := process.Processes()
		if err != nil {
			return err
		}
		for _, p := range procs {
			info := exportProcInfo(p)
			cb(info)
		}
		return nil
	})

	// getProcessInfo returns detailed info about a process by PID
	vm.Set("getProcessInfo", func(pid int64) (map[string]interface{}, error) {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return nil, err
		}
		return exportProcInfo(p), nil
	})

	// killProcess sends SIGKILL (or equivalent) to the given PID
	vm.Set("killProcess", func(pid int64) error {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return err
		}
		return p.Kill()
	})

	// suspendProcess pauses the process with the given PID
	vm.Set("suspendProcess", func(pid int64) error {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return err
		}
		return p.Suspend()
	})

	// resumeProcess resumes a previously suspended process
	vm.Set("resumeProcess", func(pid int64) error {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			return err
		}
		return p.Resume()
	})

	// listProcesses returns process summaries (bounded)
	vm.Set("listProcesses", func() ([]map[string]interface{}, error) {
		procs, err := process.Processes()
		if err != nil {
			return nil, err
		}
		out := make([]map[string]interface{}, 0, len(procs))
		for i, p := range procs {
			if i >= maxProcList {
				break
			}
			out = append(out, exportProcInfo(p))
		}
		return out, nil
	})

	// findProcesses filters processes by regex on name/cmd/exe.
	vm.Set("findProcesses", func(opts map[string]interface{}) ([]map[string]interface{}, error) {
		var (
			nameRe, cmdRe, exeRe *regexp.Regexp
			err                  error
			limit                = maxProcList
		)
		if v, ok := opts["nameRegex"].(string); ok && strings.TrimSpace(v) != "" {
			nameRe, err = regexp.Compile(v)
			if err != nil {
				return nil, err
			}
		}
		if v, ok := opts["cmdRegex"].(string); ok && strings.TrimSpace(v) != "" {
			cmdRe, err = regexp.Compile(v)
			if err != nil {
				return nil, err
			}
		}
		if v, ok := opts["exeRegex"].(string); ok && strings.TrimSpace(v) != "" {
			exeRe, err = regexp.Compile(v)
			if err != nil {
				return nil, err
			}
		}
		if v, ok := opts["limit"]; ok {
			if n, ok := v.(int64); ok && n > 0 && int(n) < limit {
				limit = int(n)
			} else if n, ok := v.(float64); ok && n > 0 && int(n) < limit {
				limit = int(n)
			}
		}

		procs, err := process.Processes()
		if err != nil {
			return nil, err
		}
		out := make([]map[string]interface{}, 0, len(procs))
		for _, p := range procs {
			info := exportProcInfo(p)
			name := info["name"].(string)
			exe := info["exe"].(string)
			cmdline, _ := info["cmdline"].([]string)
			cmdJoined := strings.Join(cmdline, " ")
			if nameRe != nil && !nameRe.MatchString(name) {
				continue
			}
			if exeRe != nil && !exeRe.MatchString(exe) {
				continue
			}
			if cmdRe != nil && !cmdRe.MatchString(cmdJoined) {
				continue
			}
			out = append(out, info)
			if len(out) >= limit {
				break
			}
		}
		return out, nil
	})

	// processConnections returns network connections for a PID (bounded).
	addHelper("processConnections", "List network connections for a process", []string{"pid"}, func() {
		vm.Set("processConnections", func(pid int64) ([]map[string]interface{}, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conns, err := gnet.ConnectionsPidMaxWithContext(ctx, "all", int32(pid), maxConnList)
			if err != nil {
				return nil, err
			}
			return exportConnections(conns), nil
		})
	})
	addHelper("processSearchText", "Search process memory for a literal string (Linux only)", []string{"pid", "needle", "opts"}, func() {
		vm.Set("processSearchText", func(pid int64, needle string, opts map[string]interface{}) (map[string]interface{}, error) {
			maxTotal := maxMemSearchTotal
			maxHits := maxMemSearchHits
			caseInsensitive := false
			if v, ok := opts["maxBytes"].(int64); ok && v > 0 && int(v) < maxTotal {
				maxTotal = int(v)
			} else if v, ok := opts["maxBytes"].(float64); ok && v > 0 && int(v) < maxTotal {
				maxTotal = int(v)
			}
			if v, ok := opts["maxHits"].(int64); ok && v > 0 && int(v) < maxHits {
				maxHits = int(v)
			} else if v, ok := opts["maxHits"].(float64); ok && v > 0 && int(v) < maxHits {
				maxHits = int(v)
			}
			if v, ok := opts["caseInsensitive"].(bool); ok && v {
				caseInsensitive = true
			}
			if runtime.GOOS != "linux" {
				return nil, fmt.Errorf("processSearchText only supported on linux")
			}
			return processSearchTextLinux(pid, needle, maxTotal, maxHits, caseInsensitive)
		})
	})
	addHelper("listProcessModules", "List mapped modules/files for a process", []string{"pid"}, func() {
		vm.Set("listProcessModules", func(pid int64) ([]map[string]interface{}, error) {
			p, err := process.NewProcess(int32(pid))
			if err != nil {
				return nil, err
			}
			mmaps, err := p.MemoryMaps(false)
			if err != nil {
				return nil, err
			}
			var out []map[string]interface{}
			for _, m := range *mmaps {
				if mm, ok := memoryMapToMap(m); ok {
					out = append(out, mm)
				}
				if len(out) >= maxListEntries {
					break
				}
			}
			return out, nil
		})
	})

	// listConnections returns recent network connections (bounded).
	vm.Set("listConnections", func() ([]map[string]interface{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conns, err := gnet.ConnectionsMaxWithContext(ctx, "all", maxConnList)
		if err != nil {
			return nil, err
		}
		return exportConnections(conns), nil
	})

	// getCPUPercent returns overall and per-CPU usage percentages over given interval (seconds)
	vm.Set("getCPUPercent", func(interval float64, percpu bool) ([]float64, error) {
		pct, err := cpu.Percent(time.Duration(interval*float64(time.Second)), percpu)
		if err != nil {
			return nil, err
		}
		return pct, nil
	})

	// getMemInfo returns memory usage statistics
	vm.Set("getMemInfo", func() (map[string]interface{}, error) {
		mi, err := mem.VirtualMemory()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"total":       mi.Total,
			"available":   mi.Available,
			"used":        mi.Used,
			"usedPercent": mi.UsedPercent,
		}, nil
	})

	// getDiskUsage returns disk usage statistics for the given path
	vm.Set("getDiskUsage", func(path string) (map[string]interface{}, error) {
		d, err := disk.Usage(path)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"path":        path,
			"total":       d.Total,
			"free":        d.Free,
			"used":        d.Used,
			"usedPercent": d.UsedPercent,
		}, nil
	})

	// listNetworkInterfaces returns the names of all network interfaces
	vm.Set("listNetworkInterfaces", func() ([]string, error) {
		ifs, err := net.Interfaces()
		if err != nil {
			// skip interface listing on permission errors
			return []string{}, nil
		}
		var out []string
		for _, iface := range ifs {
			out = append(out, iface.Name)
		}
		return out, nil
	})

	// getHostInfo returns basic host information
	vm.Set("getHostInfo", func() (map[string]interface{}, error) {
		hi, err := host.Info()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"hostname":        hi.Hostname,
			"os":              hi.OS,
			"platform":        hi.Platform,
			"platformVersion": hi.PlatformVersion,
			"uptime":          hi.Uptime,
		}, nil
	})

	// YARA integration stubs
	vm.Set("lazyLoadYara", func(libPath string) error {
		yaraLoaded = true
		yaraErr = ""
		return nil
	})
	yaraObj := vm.NewObject()
	yaraObj.Set("addRule", func(rule string) error {
		if !yaraLoaded {
			yaraErr = "YARA library not loaded"
			return errors.New(yaraErr)
		}
		yaraRules = append(yaraRules, rule)
		return nil
	})
	yaraObj.Set("scanProcess", func(pid int) []map[string]interface{} {
		if !yaraLoaded {
			return nil
		}
		return []map[string]interface{}{}
	})
	yaraObj.Set("scanFile", func(path string) []map[string]interface{} {
		if !yaraLoaded {
			return nil
		}
		var matches []map[string]interface{}
		for _, r := range yaraRules {
			matches = append(matches, map[string]interface{}{
				"rule":   truncateRuleName(r),
				"path":   path,
				"match":  false,
				"reason": "stubbed",
			})
		}
		return matches
	})
	yaraObj.Set("scanPaths", func(rule string, paths []interface{}) []map[string]interface{} {
		if !yaraLoaded {
			return nil
		}
		var matches []map[string]interface{}
		for _, p := range paths {
			if s, ok := p.(string); ok {
				matches = append(matches, map[string]interface{}{"rule": truncateRuleName(rule), "path": s, "match": false, "reason": "stubbed"})
			}
			if len(matches) >= maxListEntries {
				break
			}
		}
		return []map[string]interface{}{}
	})
	yaraObj.Set("errorString", func() string {
		return yaraErr
	})
	yaraObj.Set("scanBuffer", func(buf []byte) []map[string]interface{} {
		if !yaraLoaded {
			return nil
		}
		return []map[string]interface{}{}
	})
	yaraObj.Set("scanProcs", func(rule string, nameRegex string) []map[string]interface{} {
		if !yaraLoaded {
			return nil
		}
		re, err := regexp.Compile(nameRegex)
		if err != nil {
			yaraErr = err.Error()
			return nil
		}
		procs, _ := process.Processes()
		var matches []map[string]interface{}
		for _, p := range procs {
			name, _ := p.Name()
			if re.MatchString(name) {
				matches = append(matches, map[string]interface{}{
					"rule":    truncateRuleName(rule),
					"pid":     p.Pid,
					"process": name,
					"match":   false,
					"reason":  "stubbed",
				})
			}
			if len(matches) >= maxListEntries {
				break
			}
		}
		return matches
	})
	vm.Set("yara", yaraObj)

	// funcs returns documentation for all built-in JS helpers
	vm.Set("funcs", func() []map[string]interface{} {
		var out []map[string]interface{}
		for _, d := range helperDocs {
			out = append(out, map[string]interface{}{
				"name":   d.Name,
				"desc":   d.Description,
				"params": d.Params,
			})
		}
		return out
	})

	// Windows-specific stubs (to be implemented later)
	registerWindowsHelpers(vm)

	// rsrpcLocal performs a JSON-RPC call over a local IPC channel (domain socket or named pipe)
	// vm.Set("rsrpcLocal", func(method string, params interface{}, timeoutMs int) (interface{}, error) {
	// 	// connect to rsmon local RPC endpoint
	// 	var conn net.Conn
	// 	var err error
	// 	if runtime.GOOS == "windows" {
	// 		conn, err = winio.DialPipe(`\\.\\pipe\\socrsmon_rpc`, &winio.PipeDialConfig{Timeout: time.Duration(timeoutMs) * time.Millisecond})
	// 	} else {
	// 		conn, err = net.DialTimeout("unix", "/var/run/socrsmon.sock", time.Duration(timeoutMs)*time.Millisecond)
	// 	}
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	defer conn.Close()

	// 	// send request
	// 	reqObj := map[string]interface{}{"jsonrpc": "2.0", "method": method, "params": params, "id": fmt.Sprintf("js-%d", time.Now().UnixNano())}
	// 	data, _ := json.Marshal(reqObj)
	// 	if _, err := conn.Write(data); err != nil {
	// 		return nil, err
	// 	}

	// 	// read response
	// 	var resp struct {
	// 		Result interface{} `json:"result"`
	// 		Error  interface{} `json:"error"`
	// 	}
	// 	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
	// 		return nil, err
	// 	}
	// 	if resp.Error != nil {
	// 		return nil, fmt.Errorf("rsmon RPC error: %v", resp.Error)
	// 	}
	// 	return resp.Result, nil
	// })
}
