# JS Helper Reference

This document lists the `response-runtime` **JS helpers**.

Use it for **two things**:

- understand which helpers exist in the public safe-default build
- understand which build tag enables higher-risk helpers

The built runtime is still the **final source of truth**. To inspect the helpers in a binary:

```bash
./dist/host/active-response helpers
```

For local playbook development:

```bash
./dist/host/active-response local-run-js --playbook playbooks/hunt/hash_and_report_file.js
```

## Capability Model

The helper surface follows **three broad classes**:

- `observe`: inspect host, files, network, and process state
- `respond`: bounded containment or remediation actions such as process kill or IP block
- `control`: broader execution, mutation, or remote-action primitives that are tag-gated

**Default public builds** keep `observe` and bounded `respond` helpers available, and exclude most `control` helpers unless explicitly enabled at build time.

## Tag Matrix

| Tag | What it enables |
| --- | --- |
| none | Safe-default helper surface |
| `js_file_read` | JS file-content reads such as `readFile` and `readTextFile` |
| `js_sensitive_reads` | JS hosts/auth/registry read helpers |
| `js_unsafe_features` | JS local-control helpers such as `exec`, `writeFile`, `writeTextFile`, and local `importModule` |
| `js_enable_http_import` | `importModule` over HTTP(S) |
| `enable_http_client` | JS `httpGet` and `httpPost` |
| `js_network_probes` | JS active network probes such as `ping`, `traceroute`, DNS lookups, port reachability checks, banners, and fingerprinting |
| `js_walk_dir` | JS recursive directory walking via `walkDir` |
| `js_unsafe_with_auth` | Authenticated JS remote action helpers such as `sshExec` |

## Calling Conventions

**Common patterns**:

- file data helpers usually accept or return raw bytes, text, `base64`, or `hex`
- object-style helpers such as `firewall` and `state` group related functions
- many inspection helpers return plain JS objects or arrays of JS objects
- most helpers return an error through the runtime if the operation fails
- progress/debug helpers are transport-neutral and work in local and responder execution modes

## Safe-Default Helpers

These are available in the **default public build** unless otherwise noted.

### Runtime And Control Flow

| Helper | Purpose | Class |
| --- | --- | --- |
| `helpers()` | List runtime helper metadata | observe |
| `log(...args)` | Emit script output | observe |
| `reportProgress(payload)` | Report structured progress | observe |
| `progressStdout(chunk)` | Send stdout-like progress chunks | observe |
| `outputDebugString(msg)` | Send debug strings to the host | observe |
| `sleep(ms)` | Async delay helper | observe |
| `env(name)` | Read an environment variable | observe |
| `agentInfo()` | Return runtime and host metadata | observe |

### Identity And Host Basics

| Helper | Purpose | Class |
| --- | --- | --- |
| `whoami()` | Current user | observe |
| `uname()` | OS, arch, hostname, runtime version | observe |
| `getHostInfo()` | Host metadata via gopsutil | observe |
| `getCPUPercent(interval, percpu)` | CPU usage | observe |
| `getMemInfo()` | Memory information | observe |
| `getDiskUsage(path)` | Disk usage for a path | observe |

### Files And Directories

| Helper | Purpose | Class |
| --- | --- | --- |
| `listDir(root, opts)` | List directory entries | observe |
| `fileInfo(path, opts)` | File metadata and bounded content info | observe |
| `fileStrings(path, opts)` | Extract printable strings | observe |
| `fileEntropy(path, maxBytes)` | Estimate file entropy | observe |
| `hashFile(path, algo)` | Hash file using selected algorithm | observe |
| `hashFileSha1(path)` | SHA-1 convenience helper | observe |
| `getFileMd5(path)` | MD5 convenience helper | observe |
| `getFileSha256(path)` | SHA-256 convenience helper | observe |
| `hashBuffer(data, algo)` | Hash buffer content | observe |
| `peInfo(path)` | PE metadata for Windows binaries | observe |

### State And Serialization

| Helper | Purpose | Class |
| --- | --- | --- |
| `state.kvGet(key)` | Read persistent state | observe |
| `state.kvSet(key, val)` | Write persistent state | observe |
| `state.kvDel(key)` | Delete persistent state | observe |
| `state.logFinding(sig, payload)` | Record a finding with timestamp | observe |
| `state.lastSeen(sig)` | Look up last-seen timestamp | observe |
| `base64Encode(data)` | Base64 encode | observe |
| `base64Decode(data)` | Base64 decode | observe |
| `hexEncode(data)` | Hex encode | observe |
| `hexDecode(data)` | Hex decode | observe |
| `urlEncode(data)` | URL encode | observe |
| `urlDecode(data)` | URL decode | observe |
| `xmlParse(xml)` | Parse XML into object | observe |
| `xmlEncode(obj)` | Encode object into XML | observe |
| `iniParse(ini)` | Parse INI text | observe |
| `iniEncode(obj)` | Encode INI text | observe |
| `yamlParse(yaml)` | Parse YAML text | observe |
| `yamlEncode(obj)` | Encode YAML text | observe |
| `tomlParse(toml)` | Parse TOML text | observe |
| `tomlEncode(obj)` | Encode TOML text | observe |

### Compression And Random Utilities

| Helper | Purpose | Class |
| --- | --- | --- |
| `gzipCompress` / `gzipDecompress` | Gzip helpers | observe |
| `deflateCompress` / `deflateDecompress` | Zlib/deflate helpers | observe |
| `brotliCompress` / `brotliDecompress` | Brotli helpers | observe |
| `zstdCompress` / `zstdDecompress` | Zstandard helpers | observe |
| `lz4Compress` / `lz4Decompress` | LZ4 helpers | observe |
| `snappyCompress` / `snappyDecompress` | Snappy helpers | observe |
| `uuidv4()` | Random UUIDv4 | observe |
| `randString(n)` | Random string | observe |
| `entropy(data)` | String entropy estimate | observe |
| `domainEntropy(domain)` | Domain entropy estimate | observe |
| `tld(domain)` | Extract TLD | observe |
| `isPrivateIp(ip)` | Check private IP ranges | observe |

### Network And Service Inspection

| Helper | Purpose | Class |
| --- | --- | --- |
| `dnsCache()` | List local DNS cache entries | observe |
| `listNetworkInterfaces()` | Interface inventory | observe |
| `listIpRoutes()` | Route table inventory | observe |
| `listConnections()` | System connection inventory | observe |
| `listServices()` | OS service inventory | observe |
| `listServiceDetails()` | Service details with richer metadata | observe |
| `listInstalledApps()` | Installed application inventory | observe |
| `listAutoruns()` | Autorun inventory | observe |
| `listScheduledTasks()` | Scheduled task inventory | observe |

### Process Inspection And Containment

| Helper | Purpose | Class |
| --- | --- | --- |
| `listProcesses()` | Process inventory | observe |
| `walkProcesses(cb)` | Iterate processes through callback | observe |
| `findProcesses(opts)` | Filter process list | observe |
| `getProcessInfo(pid)` | Process metadata | observe |
| `getPidStats(pid)` | CPU/memory/uptime stats | observe |
| `pidToPath(pid)` | Resolve PID to path/cmdline | observe |
| `pathToPid(path)` | Resolve path to PIDs | observe |
| `processConnections(pid)` | List network connections for a PID | observe |
| `listProcessModules(pid)` | List mapped modules/files for a process | observe |
| `processSearchText(pid, needle, opts)` | Search process memory for text | observe |
| `killProcess(pid, signal?)` | Terminate a process | respond |
| `suspendProcess(pid)` | Suspend a process | respond |
| `resumeProcess(pid)` | Resume a process | respond |

### Firewall And Bounded Response Helpers

| Helper | Purpose | Class |
| --- | --- | --- |
| `firewall.blockIp(ip)` | Add bounded IP block rule | respond |
| `firewall.unblockIp(ip)` | Remove bounded IP block rule | respond |
| `firewall.listBlockedIps()` | List runtime-created IP blocks | observe |
| `firewall.flushBlockList()` | Remove runtime-created IP blocks | respond |
| `firewall.blockExe(path)` | Windows-only outbound executable block | respond |
| `firewall.unblockExe(path)` | Remove Windows executable block | respond |

### Platform-Specific Helpers

| Helper | Purpose | Class | Platform |
| --- | --- | --- | --- |
| `winWmicQuery(query)` | Safe WMIC query helper | observe | Windows |
| `lazyLoadYara(libPath)` / `yara.*` | Optional YARA integration | observe | platform-dependent |

## Tag-Gated Helpers

These helpers are **intentionally excluded** from the **safe-default public build** unless their build tag is enabled.

### `js_file_read`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `readFile(path, encoding?)` | Read arbitrary file bytes or text | broad local file-content access |
| `readTextFile(path)` | Read UTF-8 text file | broad local file-content access |

### `js_sensitive_reads`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `hostsFileListEntries()` | Parse local hosts file entries | local trust-boundary and redirect data |
| `authFailures()` | Read authentication failure summaries from local logs | sensitive local log access |
| `regListValues(key)` | Registry value listing | sensitive Windows configuration access |
| `regListSubkeys(key)` | Registry subkey listing | sensitive Windows configuration access |
| `regGet(key, value)` | Registry value read | sensitive Windows configuration access |

### `js_unsafe_features`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `writeFile(path, data, encoding?)` | Write arbitrary file content | local filesystem mutation |
| `writeTextFile(path, data)` | Write UTF-8 text | local filesystem mutation |
| `exec(cmd, opts?)` | Run a local command | arbitrary endpoint execution |
| `importModule(path)` | Load JS from local file | local code loading |

### `js_enable_http_import`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `importModule("https://...")` | Load JS module over HTTP(S) | remote code loading |

`js_enable_http_import` only matters when `js_unsafe_features` is **also enabled**.

### `enable_http_client`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `httpGet(url, encoding?)` | HTTP GET client | outbound network / exfil path |
| `httpPost(url, opts)` | HTTP POST client | outbound network / exfil path |

### `js_network_probes`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `ping(host, count?, callback?)` | ICMP reachability probe | active network behavior from endpoint |
| `traceroute(host, maxHops?, callback?)` | Route probing | active network behavior from endpoint |
| `dnsLookup(name)` | Resolve hostname to IPs | outbound name resolution from endpoint |
| `reverseDNS(ip)` | PTR lookup | outbound name resolution from endpoint |
| `dnsTrace(name)` | Query DNS trace summary | active resolver interaction |
| `httpFingerprint(url, opts)` | Bounded HTTP fingerprinting | outbound web probing |
| `tlsFingerprint(host, port, timeoutMs)` | TLS certificate metadata | outbound TLS probing |
| `ja3(host, port)` | JA3 fingerprint from a custom ClientHello | outbound TLS probing |
| `whoisSummary(target)` | Trimmed WHOIS summary | outbound network query |
| `tcpIsOpen(host, port, timeoutMs)` | TCP reachability probe | active network behavior from endpoint |
| `udpIsOpen(host, port, timeoutMs)` | UDP reachability probe | active network behavior from endpoint |
| `tcpBanner(host, port, timeoutMs)` | TCP banner grab | outbound service probing |
| `tlsBanner(host, port, timeoutMs)` | TLS banner/metadata | outbound service probing |
| `multiPortCheck(host, ports, timeoutMs)` | Probe multiple ports | active network scanning from endpoint |

### `js_walk_dir`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `walkDir(root, cb)` | Walk a directory tree recursively | broad filesystem discovery across endpoint |

### `js_unsafe_with_auth`

| Helper | Purpose | Why gated |
| --- | --- | --- |
| `sshExec(urlOrHost, opts)` | Run a command over SSH | remote authenticated action |

## Example Playbooks

**Safe-default examples** live under:

- [playbooks/hunt](../playbooks/hunt/README.md)
- [playbooks/contain](../playbooks/contain/README.md)

**Useful starting points**:

- [playbooks/hunt/hash_and_report_file.js](../playbooks/hunt/hash_and_report_file.js)
- [playbooks/hunt/collect_process_network_context.js](../playbooks/hunt/collect_process_network_context.js)
- [playbooks/contain/block_alert_source_ip.js](../playbooks/contain/block_alert_source_ip.js)
- [playbooks/contain/contain_process_and_block_ip.js](../playbooks/contain/contain_process_and_block_ip.js)

## Contribution Guidance

When adding or changing helpers:

- update this reference
- state whether the helper is `observe`, `respond`, or `control`
- state whether it is safe-default or tag-gated
- add or update examples when the helper changes playbook ergonomics

When contributing playbooks:

- document required helpers at the top of the playbook
- note whether the playbook is safe-default or tag-dependent
- prefer bounded helpers over broad execution primitives
