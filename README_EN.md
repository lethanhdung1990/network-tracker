# 🛡️ network-tracker - Lightweight Background Network Monitor for Windows in Go (Golang)

> **Master Project Blueprint & Roadmap**  
> *Optimized Architecture Version: 100% Native Go (Golang) compilation to machine code, ultra-lightweight (<12MB RAM, 0.01% CPU), packaged into a single standalone `.exe` file, interfacing directly with Windows Kernel APIs.*

---

## 1. Problem Statement

### 1.1. Real-World User Concerns
1. **Computers silently sending requests to unwanted destinations:**
   - Adware, telemetry, background extensions, or spyware covertly establish connections to Command & Control (C2) servers or data-harvesting endpoints.
   - Difficult to identify which Windows `.exe` executable is truly originating that socket connection.
2. **Processes constantly transmitting data causing network congestion and system lag:**
   - Errant processes stuck in infinite retry loops continuously send requests or silently upload/download heavy data in the background, degrading responsiveness and hogging bandwidth.
3. **Ephemeral Processes (Short-Lived Sockets):**
   - Commands like `curl.exe`, hidden PowerShell scripts, or transient malware open a socket, transmit a single request, and terminate immediately within 50ms - 100ms. By the time periodic polling tools check, the process has exited, leaving ghost sockets with no identifiable origin.
4. **Limitations of existing tools (such as Wireshark):**
   - **No Process Attribution:** Wireshark captures raw packets at the network driver layer (Npcap); it only observes IP addresses and ports, but **cannot determine the Windows process name (`.exe`) or `PID`** that initiated the socket.
   - **Too heavy for 24/7 continuous operation:** Wireshark captures and stores full packet payloads, consuming gigabytes of RAM and creating massive dump files that cause system freezes.

---

## 2. Project Goals

- 🪶 **Ultra-Lightweight & Maximum Resource Efficiency (Go Native):**
  - **Memory footprint in background:** Only **~8 - 12 MB RAM** (1/3 of a Python equivalent, less than 1/1000th of an 8GB RAM system).
  - **CPU utilization:** Near zero (**0.0% - 0.01%**).
  - **Single standalone `.exe` package (~6MB):** Completely self-contained; no need to install Python, Go, or any runtime dependencies on target machines.
- 🎯 **Direct Socket-to-Process Attribution:** Every inbound and outbound connection is resolved to its exact `PID`, `Process Name` (e.g., `chrome.exe`, `curl.exe`), and `Full Executable Path` (instantly flagging binaries running from `Temp`, `AppData`, or `Public`).
- ⚡ **Capture Ephemeral Processes:** Employs a Triple Correlation mechanism (Process Lifecycle Cache + TCP `TIME_WAIT` + DNS Cache) with rapid polling cycles of **100ms - 200ms** without heating up the CPU.
- 🌐 **Domain Name Resolution:** Integrates the Windows DNS Client Cache and asynchronous Reverse DNS to translate raw IP addresses into clear domain names (e.g., `github.com`, `google.com`).
- 🚨 **Anomaly & Congestion Alerts:**
  - `HIGH_FREQUENCY_BURST`: Alerts when an application opens a rapid flurry of connections within seconds.
  - `SUSPICIOUS_EXECUTABLE_PATH`: Flags binaries launched from `Temp`, `AppData\Roaming`, or `C:\Users\Public`.
  - `UNUSUAL_DESTINATION_PORT`: Warns about connections to abnormal or non-standard ports.
  - `HEAVY_BANDWIDTH_BURST`: Flags processes consuming excessive upload or download bandwidth.
- 📁 **Structured Log Management:**
  - Dedicated daily directory (`logs/YYYY-MM-DD/`).
  - Strict size capping at **100MB per file** with automatic rotation.
  - Formatted text templates, JSON Lines, and an embedded SQLite database for analytics.
- 🖥️ **Console TUI & Self-Test Suite:** Live interactive dashboard in the terminal and a built-in automated test suite.

---

## 3. System Architecture

### 3.1. Concurrent Goroutines Pipeline Diagram

```text
     ┌─────────────────────────────────────────────────────────────┐
     │                   WINDOWS OPERATING SYSTEM                  │
     ├──────────────────────────────┬──────────────────────────────┤
     │  Windows Socket Kernel Table │  Windows DNS Client Cache    │
     │      (iphlpapi.dll)          │        (dnsapi.dll)          │
     └──────────────┬───────────────┴──────────────┬───────────────┘
                    │                              │
                    ▼                              ▼
    ┌───────────────────────────────┐ ┌───────────────────────────┐
    │ Goroutine 1: Socket Poller    │ │ Goroutine 2: DNS Resolver │
    │ (GetExtendedTcpTable / UDP)   │ │ (DNS Cache Sync + Rev DNS)│
    └───────────────┬───────────────┘ └────────────┬──────────────┘
                    │                              │
                    ▼                              ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Goroutine 3: Correlation & Process Resolver Engine          │
    │  - Triple Correlation (Process Lifecycle Cache + TIME_WAIT) │
    │  - Binary Image Path Resolution (QueryFullProcessImageNameW)│
    │  - Socket + PID + Domain Aggregation                        │
    └───────────────┬──────────────────────────────┬──────────────┘
                    │                              │
                    ▼                              ▼
    ┌───────────────────────────────┐ ┌───────────────────────────┐
    │ Goroutine 4: Anomaly Detector │ │ Goroutine 5: I/O Monitor  │
    │ (Burst, Path, Port, Blacklist)│ │ (GetProcessIoCounters)    │
    └───────────────┬───────────────┘ └────────────┬──────────────┘
                    │                              │
                    └───────────────┬──────────────┘
                                    ▼
    ┌─────────────────────────────────────────────────────────────┐
    │ Goroutine 6: Multi-Channel Writer (Buffered Channel)        │
    │  ├─ logs/YYYY-MM-DD/network.log    (Max 100MB Rotation)     │
    │  ├─ logs/YYYY-MM-DD/alerts.log     (Max 100MB Rotation)     │
    │  ├─ logs/YYYY-MM-DD/connections.jsonl                       │
    │  └─ data/network_history.db        (SQLite Analytics)       │
    └─────────────────────────────────────────────────────────────┘
```

### 3.2. Detailed 5 Architectural Layers in Go

| Functional Layer | Responsibility & Role | Finalized Go Technologies |
|---|---|---|
| **1. Connection & Process Monitor** | Direct Windows Native API calls via `syscall` / `golang.org/x/sys/windows`. Tracks `ESTABLISHED` and `TIME_WAIT` states. | `iphlpapi.dll` (`GetExtendedTcpTable`, `GetExtendedUdpTable`), `kernel32.dll` (`OpenProcess`, `QueryFullProcessImageNameW`). **Execution speed: ~40 microseconds/poll**. |
| **2. DNS Resolution Layer** | Reads Windows DNS Client Cache and performs asynchronous Reverse DNS. | Cache reading via Windows API / PowerShell JSON stream, `net.LookupAddr` in background goroutines with LRU cache. |
| **3. Bandwidth & Anomaly Engine** | Measures per-PID I/O transfer rates and detects connection surges using a sliding window. | `kernel32.dll` (`GetProcessIoCounters`), thread-safe ring buffer. |
| **4. Logging & Storage Layer** | Date-partitioned logging (`logs/YYYY-MM-DD/`), automatic 100MB file rotation. Writes text templates, JSONL, and SQLite. | Standard library `os`, `io`, `encoding/json`, `log/slog`, Pure-Go SQLite (`modernc.org/sqlite` - zero CGO/GCC required). |
| **5. Management & UI** | Unified CLI controller, background execution via Windows Service / Detached process, live TUI dashboard. | Terminal TUI dashboard via lightweight Go libraries or ANSI escapes, channel listening on `os.Interrupt`. |

---

## 4. Finalized Tech Decisions

1. **Programming Language:** **Go (Golang 1.26.4)**
   - Pre-installed at `C:\Program Files\Go\bin\go.exe`.
   - Compiles to **1 standalone `.exe` executable (~6MB)**, completely independent of external runtimes.
2. **Windows API Communication:** Standard packages `syscall` and `golang.org/x/sys/windows`
   - Go struct memory layouts match Windows C structs 1:1 (`Zero-copy`).
   - System call invocation is up to 90 times faster than Python, enabling high-frequency scanning (100ms - 200ms) to capture fleeting connections while maintaining CPU usage at 0.01%.
3. **Configuration:** Standard `config.json` format parsed using Go's built-in `encoding/json`.
4. **Monitoring Interface:** **Console TUI (Terminal User Interface)**
   - Runs directly in Console/PowerShell, rendering dynamic tables (network throughput, active connections, alerts).
   - Instant opening/closing; terminating the TUI does not interrupt the background monitoring engine.
   - Smooth pagination configured via `rows_per_page` in `config.json`, `Space` key to pause/resume, and navigation with `k/j/h/l` or arrow keys.
5. **Native Windows Service (`services.msc`):**
   - Deep integration with Windows Service Control Manager (SCM) via standard `golang.org/x/sys/windows/svc` and `svc/mgr`.
   - Starts automatically during Windows boot before user login; status manageable via `services.msc`.
   - **Resolves Session 0 Isolation:** Automatically detects the executable directory and redirects the Working Directory to the project root, ensuring correct access to `config.json`, `logs/`, and `data/`.
   - Supports dual modes: Enterprise Windows Service (`services.msc`) and hidden user daemon (`start_background.bat`).
6. **Zero External Dependencies:** Strictly no `tshark.exe`, no Npcap driver required. 100% pure Go code.

---

## 5. Ephemeral Process Handling

One of the most difficult challenges in network monitoring is handling **processes that make a request and terminate within 50ms - 100ms** (e.g., `curl.exe`, automated background scripts sending a single HTTP POST and exiting).

`network-tracker` thoroughly solves this using a **Triple Correlation Mechanism**:

```text
[ 1. Process Lifecycle Cache ] ──┐
  (Retains recently spawned PID) │
                                 ├──► [ NETWORK-TRACKER CORRELATOR ] ──► Log Output: "curl.exe (PID 8812)
[ 2. TCP TIME_WAIT Table ]    ──┤      (Correlates PID + Socket + DNS)      connected to api.abc.com and exited!"
  (Socket persists after exit)   │
                                 │
[ 3. Windows DNS Client Cache ] ──┘
  (Recently resolved domain)
```

1. **Process Lifecycle Cache:**
   - A dedicated goroutine monitors newly created processes across Windows.
   - Any newly spawned process—even if it lives for only 20 milliseconds—has its `PID`, `Executable Name`, and `Full Image Path` preserved in cache for **60 seconds**.
2. **TCP `TIME_WAIT` State Polling:**
   - Under the TCP specification, when a socket closes, Windows retains it in the `TIME_WAIT` state for **30 - 120 seconds**.
   - `network-tracker` polls the `TIME_WAIT` table via `GetExtendedTcpTable` and cross-references against the Lifecycle Cache to recover the identity of the terminated `.exe`.
3. **Sub-Millisecond Polling Speed (100ms):**
   - Since calling the Win32 API in Go takes only ~0.04ms with zero heap allocations, `network-tracker` safely polls every **100ms** to capture fleeting processes before they evaporate.

---

## 6. Project Structure

The project strictly follows standard Go project conventions:

```text
network-tracker/
├── README.md                      # Master technical documentation in Vietnamese
├── README_EN.md                   # Master technical documentation in English (This file)
├── ReleaseNote.md                 # Release notes in Vietnamese
├── ReleaseNote_EN.md              # Release notes in English
├── go.mod                         # Go module definition: module network-tracker
├── go.sum                         # Dependency checksums
├── config.json                    # Central configuration file in JSON (Monitor, Alerts, Logs, UI...)
│
├── cmd/
│   └── tracker/
│       └── main.go                # Unified CLI entry point (service, start, stop, status, monitor, report, test)
│
├── internal/
│   ├── winapi/                    # Direct Windows Native Win32 API calls via syscall
│   │   ├── tcp.go                 # GetExtendedTcpTable (IPv4/IPv6, PID, State)
│   │   ├── udp.go                 # GetExtendedUdpTable (IPv4/IPv6, PID)
│   │   ├── process.go             # OpenProcess, QueryFullProcessImageNameW, Process IoCounters
│   │   └── type.go                # C-compatible struct definitions (MIB_TCPROW_OWNER_PID...)
│   │
│   ├── config/
│   │   └── config.go              # Load & validate config.json (supports pagination ui.rows_per_page)
│   │
│   ├── monitor/
│   │   ├── connection.go          # Socket snapshotting & CONNECT / CLOSE diffing
│   │   ├── dns.go                 # Windows DNS Client Cache + Reverse DNS resolver + cache
│   │   ├── bandwidth.go           # Per-PID real-time I/O transfer rate calculation
│   │   └── lifecycle.go           # Process Lifecycle Cache capturing ephemeral processes (60s)
│   │
│   ├── anomaly/
│   │   └── detector.go            # Detects bursts, sensitive paths, unusual ports, heavy traffic
│   │
│   ├── logger/
│   │   └── logger.go              # Logging: daily folder logs/YYYY-MM-DD/, max 100MB rotation
│   │
│   ├── storage/
│   │   └── storage.go             # SQLite storage (Pure-Go SQLite modernc.org/sqlite, WAL mode)
│   │
│   └── service/
│       ├── windows_service.go     # Native Windows Service (svc.Handler, SCM install/uninstall/status)
│       └── daemon.go              # Detached background process management (PID file, graceful shutdown)
│
├── ui/
│   └── monitor.go                 # Live Terminal TUI Dashboard (Bubble Tea + Lip Gloss, pagination, pause)
│
├── dist/
│   └── network-tracker.exe        # Standalone compiled binary (~6MB independent executable)
│
├── build.bat                      # 1-Click build script: Compiles source to dist/network-tracker.exe
├── install_service.bat            # 1-Click shortcut: Registers & starts Windows Service (Run as Admin)
├── uninstall_service.bat          # 1-Click shortcut: Stops & removes Windows Service (Run as Admin)
├── start_background.bat           # 1-Click shortcut: Starts hidden background daemon (User mode)
├── stop_background.bat            # 1-Click shortcut: Stops background daemon process
├── monitor.bat                    # 1-Click shortcut: Launches interactive live TUI dashboard
│
├── logs/                          # Log storage directory (automatically partitioned by date)
│   ├── tracker.pid                # PID file tracking the running background process (detached mode)
│   ├── 2026-09-15/                # Date-specific directory (YYYY-MM-DD)
│   │   ├── network.log            # Daily connection log (max 100MB, automatic rotation)
│   │   ├── network_1.log          # Rotated file if network.log reaches 100MB
│   │   ├── alerts.log             # Daily security alert log (max 100MB)
│   │   ├── alerts_1.log           # Rotated file if alerts.log reaches 100MB
│   │   └── connections.jsonl      # (Optional) Daily JSON Lines stream (max 100MB)
│   └── 2026-09-16/                # Automatically creates new folder on next day (00:00:00)
│
└── data/                          # Database directory (automatically created)
    └── network_history.db         # SQLite database storing complete history for stats and queries
```

---

## 7. Detailed Logging Structure & Configuration Template (`config.json`)

### 7.1. Standard Configuration Template (`config.json`)

```json
{
  "monitor": {
    "scan_interval_ms": 200,
    "track_tcp": true,
    "track_udp": true,
    "ignore_loopback": true,
    "ignore_lan": false,
    "trusted_processes": [
      "System",
      "svchost.exe"
    ]
  },
  "dns": {
    "enabled": true,
    "cache_size": 4096,
    "timeout_ms": 1500
  },
  "alerts": {
    "burst_threshold": 25,
    "burst_window_seconds": 10,
    "bandwidth_spike_bytes_per_sec": 5242880,
    "suspicious_paths": [
      "\\AppData\\Local\\Temp",
      "\\AppData\\Roaming",
      "\\Users\\Public",
      "\\Windows\\Temp"
    ],
    "alert_unusual_ports": true,
    "standard_ports": [80, 443, 53, 22, 123, 8080, 8443, 5228, 5222],
    "blacklist_domains": [],
    "blacklist_ips": []
  },
  "logging": {
    "log_dir": "logs",
    "daily_folder": true,
    "max_file_size_mb": 100,
    "backup_count": 20,
    "enable_text_log": true,
    "enable_jsonl": true,
    "format_template": "[{timestamp}] [{event:<8}] {process_name:<18} (PID: {pid:<5}) -> {remote_ip}:{remote_port:<5} [{domain}] | Proto: {protocol} | State: {state} | Path: {process_path}",
    "timestamp_format": "2006-01-02 15:04:05"
  },
  "database": {
    "enabled": true,
    "db_path": "data/network_history.db",
    "retention_days": 30
  },
  "ui": {
    "rows_per_page": 20
  },
  "service": {
    "name": "NetworkTracker",
    "display_name": "Network Tracker Monitoring Service",
    "description": "24/7 background network connection monitor, ephemeral process tracker, and anomaly detection system.",
    "executable_path": "dist/network-tracker.exe",
    "candidate_paths": [
      "dist/network-tracker.exe",
      "network-tracker.exe"
    ]
  }
}
```

---

### 7.2. Detailed Log File Formats

#### 1. File `logs/YYYY-MM-DD/network.log` (Human-Readable Formatted Text)
- **Size Limit:** Maximum **100MB / file**, automatically rotating to `network_1.log`, `network_2.log`.
- **Field Structure:**
  `[TIMESTAMP] [EVENT] [PROCESS_NAME] (PID) -> [REMOTE_IP:PORT] [DOMAIN] | Proto: [PROTO] | State: [STATE] | Path: [EXE_PATH]`
- **Sample Lines:**
  ```text
  [2026-09-15 14:30:01] [CONNECT ] chrome.exe         (PID: 14220) -> 142.250.190.46:443   [google.com] | Proto: TCP | State: ESTABLISHED | Path: C:\Program Files\Google\Chrome\Application\chrome.exe
  [2026-09-15 14:30:05] [CONNECT ] curl.exe           (PID: 8812 ) -> 104.21.23.45:443     [api.abc.com] | Proto: TCP | State: TIME_WAIT [PROCESS_EXITED] | Path: C:\Windows\System32\curl.exe
  [2026-09-15 14:30:12] [CLOSE   ] chrome.exe         (PID: 14220) -> 142.250.190.46:443   [google.com] | Proto: TCP | State: TIME_WAIT | Path: C:\Program Files\Google\Chrome\Application\chrome.exe
  ```

#### 2. File `logs/YYYY-MM-DD/alerts.log` (Security Alerts & Congestion Audit Log)
- **Size Limit:** Maximum **100MB / file**, automatically rotating to `alerts_1.log`.
- **Field Structure:**
  `[TIMESTAMP] [ALERT:LEVEL] [ALERT_TYPE] [MESSAGE] | Process: [NAME] (PID) | Endpoint: [IP:PORT] ([DOMAIN]) | Details: [JSON_METADATA]`
- **Sample Lines:**
  ```text
  [2026-09-15 14:30:15] [ALERT:HIGH] [HIGH_FREQUENCY_BURST] Process bad_tool.exe opened 35 connections in 10s (Threshold: 25) | Process: bad_tool.exe (8812) | Endpoint: 104.21.23.45:443 | Details: {"connections_in_window": 35, "window_sec": 10}
  [2026-09-15 14:30:20] [ALERT:HIGH] [SUSPICIOUS_EXECUTABLE_PATH] Process running from suspicious path: C:\Users\Admin\AppData\Local\Temp\miner.exe | Process: miner.exe (9912) | Endpoint: 185.220.101.5:4444 (unknown) | Details: {"rule": "AppData\\Local\\Temp"}
  [2026-09-15 14:30:30] [ALERT:HIGH] [HEAVY_BANDWIDTH_BURST] Process background_sync.exe consuming heavy network I/O: 8.50 MB/s | Process: background_sync.exe (3120) | Endpoint: 13.107.4.52:443 | Details: {"upload_kb_s": 8700, "download_kb_s": 200}
  ```

#### 3. File `logs/YYYY-MM-DD/connections.jsonl` (JSON Stream Data)
- **Purpose:** Each line is an independent JSON object, optimized for parsing, log shippers, or SIEM/ELK ingest. Max 100MB per file.

#### 4. SQLite Database (`data/network_history.db`)
- Uses Pure-Go driver `modernc.org/sqlite` (no GCC or CGO needed).
- Contains `connections` and `alerts` tables used by `network-tracker report`.

---

## 8. Step-by-Step Execution Roadmap

### Phase 1: Go Project Initialization & Win32 Native Syscalls
- Initialize `go.mod` (module `network-tracker`).
- Implement `internal/winapi`:
  - `tcp.go`: Calls `GetExtendedTcpTable` (IPv4 & IPv6).
  - `udp.go`: Calls `GetExtendedUdpTable` (IPv4 & IPv6).
  - `process.go`: Calls `OpenProcess`, `QueryFullProcessImageNameW`, `GetProcessIoCounters`.
- Implement `internal/config`: Loads and validates `config.json`.

### Phase 2: Monitoring Core, DNS & Ephemeral Process Tracking
- Implement `internal/monitor/connection.go`: Socket snapshotting, `CONNECT`/`CLOSE` diffing.
- Implement `internal/monitor/lifecycle.go`: Process Lifecycle Cache retaining new PIDs for 60s.
- Implement `internal/monitor/dns.go`: Windows DNS Client Cache sync and async reverse DNS.
- Implement `internal/monitor/bandwidth.go`: Real-time upload/download I/O rate calculation.

### Phase 3: Anomaly Engine & Multi-Channel Logging
- Implement `internal/anomaly/detector.go`: Detects burst spam, sensitive paths, weird ports, heavy traffic.
- Implement `internal/logger/logger.go`: Daily folder creation `logs/YYYY-MM-DD/`, 100MB file rotation (`network.log`, `alerts.log`).
- Implement `internal/storage/storage.go`: SQLite storage with batch insertions and WAL mode.

### Phase 4: Background Service & Management CLI
- Implement `internal/service/daemon.go`: Manages hidden background execution, writes `logs/tracker.pid`, handles clean shutdown on `SIGINT`/`SIGTERM`.
- Implement `cmd/tracker/main.go` with commands: `start`, `stop`, `status`, `report`, `test`, `monitor`, `service`.
- Create `build.bat`: 1-second compilation to `dist/network-tracker.exe`.
- Create `start_background.bat`, `stop_background.bat`, `monitor.bat`.

### Phase 5: TUI Dashboard & 6-Stage Self-Test
- Implement `ui/monitor.go`: Real-time live terminal dashboard (Bubble Tea + Lip Gloss).
- Interface stability mechanisms: Static sorting by alert level and process name, sticky cursor, preserves current page (prevents jumping back to page 1).
- Page size configurable via `ui.rows_per_page` in `config.json`.
- Shortcuts: `Space` (Pause/Resume), `j/k/Down/Up` (Cursor navigation), `h/l/Left/Right` (Pagination), `q` (Quit).
- Implement `network-tracker.exe test`: Runs 6 comprehensive verification tests.

### Phase 6: Native Windows Service Integration (`services.msc`)
- Implement `internal/service/windows_service.go`: Full `svc.Handler` (`Execute`) implementation and SCM connection (`mgr.Mgr`).
- Automatic SCM context detection (`svc.IsWindowsService()`): Automatically switches to service mode during Windows boot.
- **Resolves Session 0 Isolation:** `service.SetupWorkingDirectory()` detects binary location and switches working directory from `C:\Windows\System32` to project root to load `config.json`, write `logs/`, and database `data/`.
- Non-admin status queries: Allows standard users to check service status (`service status`) with `SC_MANAGER_CONNECT` + `SERVICE_QUERY_STATUS`.
- 1-click batch utilities with automatic UAC elevation: `install_service.bat`, `uninstall_service.bat`.

---

## 9. System Operations & User Manual

### 9.1. Management via Native Windows Service (`services.msc`) - RECOMMENDED FOR 24/7 USE

Windows Service mode ensures continuous 24/7 background operation, auto-starts on system boot before user login, and cannot be accidentally closed by terminating terminal windows.

#### 1. Install Windows Service (Requires Administrator privileges):
- **Method 1 (1-Click):** Right-click `install_service.bat` -> Select **Run as administrator**.
- **Method 2 (CLI):** Open cmd/PowerShell as Administrator and run:
  ```powershell
  .\dist\network-tracker.exe service install
  ```
- **Result:** The service **`NetworkTracker`** (Display Name: *Network Tracker Monitoring Service*) is registered with `Automatic` startup. Check it via `services.msc`.

#### 2. Starting, stopping, and checking service status:
```powershell
# Start service
.\dist\network-tracker.exe service start

# Stop service
.\dist\network-tracker.exe service stop

# Query service status (Standard user rights sufficient)
.\dist\network-tracker.exe service status
```

#### 3. Uninstall Windows Service:
- **Method 1 (1-Click):** Right-click `uninstall_service.bat` -> Select **Run as administrator**.
- **Method 2 (CLI):** Open cmd/PowerShell as Admin and run:
  ```powershell
  .\dist\network-tracker.exe service uninstall
  ```

---

### 9.2. Management via Detached User Background Mode

If you prefer not to install a system service and only want to run it during the current user session:
- **Start detached daemon:** Double-click `start_background.bat` or run `.\dist\network-tracker.exe start --background`.
- **Check status:** Run `.\dist\network-tracker.exe status`.
- **Stop daemon:** Double-click `stop_background.bat` or run `.\dist\network-tracker.exe stop`.

---

### 9.3. Launching the Interactive Live TUI Monitor

At any time (whether running as Windows Service or as a detached daemon), you can open the TUI dashboard:
- Double-click `monitor.bat` or run:
  ```powershell
  .\dist\network-tracker.exe monitor
  ```
- **Keyboard Controls:**
  - `Space`: Pause (PAUSE) or Resume (RESUME) updates to inspect specific connections.
  - `↑ / k`: Move selection up.
  - `↓ / j`: Move selection down.
  - `← / h`: Navigate to the previous page.
  - `→ / l`: Navigate to the next page.
  - `q` or `Ctrl+C`: Exit monitor (does not affect the background monitoring service).
  - Selected Connection Box at the bottom shows: *Process Name, PID, Destination, Socket State, Bandwidth, and highlighted Security Alerts*.

---

### 9.4. Daily Reporting & 6-Stage Self-Test

- **Generate daily summary report:**
  ```powershell
  .\dist\network-tracker.exe report
  ```
- **Run comprehensive 6-stage self-test suite:**
  ```powershell
  .\dist\network-tracker.exe test
  ```

---

## 10. Developer Starter Guide

Step-by-step instructions for developers building and extending the codebase by hand:

### Step 1: Initialize Go Module & Create Folder Layout

Open PowerShell in project folder and execute:

```powershell
# 1. Initialize Go module
go mod init network-tracker

# 2. Create complete folder structure following Go Layout
New-Item -ItemType Directory -Force cmd/tracker, internal/winapi, internal/config, internal/monitor, internal/anomaly, internal/logger, internal/storage, internal/service, ui, logs, data
```

---

### Step 2: Create Initial Configuration File (`config.json`)

Create `config.json` in project root with sample configuration:

```json
{
  "monitor": {
    "scan_interval_ms": 200,
    "track_tcp": true,
    "track_udp": true,
    "ignore_loopback": true,
    "ignore_lan": false,
    "trusted_processes": ["System", "svchost.exe"]
  },
  "dns": {
    "enabled": true,
    "cache_size": 4096,
    "timeout_ms": 1500
  },
  "alerts": {
    "burst_threshold": 25,
    "burst_window_seconds": 10,
    "bandwidth_spike_bytes_per_sec": 5242880,
    "suspicious_paths": [
      "\\AppData\\Local\\Temp",
      "\\AppData\\Roaming",
      "\\Users\\Public",
      "\\Windows\\Temp"
    ],
    "alert_unusual_ports": true,
    "standard_ports": [80, 443, 53, 22, 123, 8080, 8443, 5228, 5222],
    "blacklist_domains": [],
    "blacklist_ips": []
  },
  "logging": {
    "log_dir": "logs",
    "daily_folder": true,
    "max_file_size_mb": 100,
    "backup_count": 20,
    "enable_text_log": true,
    "enable_jsonl": true,
    "format_template": "[{timestamp}] [{event:<8}] {process_name:<18} (PID: {pid:<5}) -> {remote_ip}:{remote_port:<5} [{domain}] | Proto: {protocol} | State: {state} | Path: {process_path}",
    "timestamp_format": "2006-01-02 15:04:05"
  },
  "database": {
    "enabled": true,
    "db_path": "data/network_history.db",
    "retention_days": 30
  }
}
```

---

### Step 3: Windows Native API Programming Guide in Go (`internal/winapi/`)

This is the most critical technical section. You invoke Windows DLLs directly without CGO:

#### 1. Define DLLs and function pointers:
In Go, use `syscall.NewLazyDLL`:
```go
package winapi

import (
    "syscall"
    "unsafe"
)

var (
    modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
    procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
    procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")

    modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
    procOpenProcess               = modKernel32.NewProc("OpenProcess")
    procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
    procGetProcessIoCounters      = modKernel32.NewProc("GetProcessIoCounters")
    procCloseHandle               = modKernel32.NewProc("CloseHandle")
)
```

#### 2. Declare Windows C-compatible Structs:
Memory alignment must match Windows SDK 100%:
```go
// Struct representing a single TCP socket with owning PID
type MIB_TCPROW_OWNER_PID struct {
    State      uint32
    LocalAddr  uint32
    LocalPort  uint32
    RemoteAddr uint32
    RemotePort uint32
    OwningPid  uint32
}

// Table constants
const (
    TCP_TABLE_OWNER_PID_ALL = 5
    AF_INET                 = 2  // IPv4
    AF_INET6                = 23 // IPv6
)
```

#### 3. IP and Port Byte Order Conversion (Network Byte Order):
Windows stores IP and Port in Network Endian format. Convert them as follows:
```go
import (
    "encoding/binary"
    "net"
)

// Convert uint32 to IPv4 string
func ParseIPv4(addr uint32) string {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, addr)
    return ip.String()
}

// Convert uint32 to Port integer
func ParsePort(port uint32) int {
    return int(binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)}))
}
```

#### 4. Resolve binary image path from PID:
```go
const (
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

func GetProcessPath(pid uint32) (string, error) {
    handle, _, _ := procOpenProcess.Call(
        uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
        0,
        uintptr(pid),
    )
    if handle == 0 {
        return "", syscall.GetLastError()
    }
    defer procCloseHandle.Call(handle)

    var buf [1024]uint16
    size := uint32(len(buf))
    ret, _, _ := procQueryFullProcessImageName.Call(
        handle,
        0,
        uintptr(unsafe.Pointer(&buf[0])),
        uintptr(unsafe.Pointer(&size)),
    )
    if ret == 0 {
        return "", syscall.GetLastError()
    }
    return syscall.UTF16ToString(buf[:size]), nil
}
```

---

### Step 4: CLI Entry Point Architecture (`cmd/tracker/main.go`)

Skeleton CLI handling control commands and auto-detecting Windows Service:

```go
package main

import (
    "fmt"
    "os"

    "golang.org/x/sys/windows/svc"
    "network-tracker/internal/config"
    "network-tracker/internal/service"
)

func main() {
    // 1. Auto-switch Working Directory to project root (fixes Session 0 C:\Windows\System32)
    service.SetupWorkingDirectory()

    cfg, _ := config.LoadConfig("config.json")

    // 2. If launched under Windows SCM, switch immediately to Windows Service mode
    isService, _ := svc.IsWindowsService()
    if isService {
        service.RunAsWindowsService(cfg)
        return
    }

    if len(os.Args) < 2 {
        printHelp()
        return
    }

    command := os.Args[1]
    switch command {
    case "service":
        handleService()
    case "start":
        handleStart(cfg)
    case "stop":
        handleStop()
    case "status":
        handleStatus()
    case "monitor":
        handleMonitor(cfg)
    case "report":
        handleReport(cfg)
    case "test":
        handleTest(cfg)
    default:
        printHelp()
    }
}
```

---

### Step 5: Compilation & Testing Commands

1. **1-Click Compilation with `build.bat` or Go command:**
   ```powershell
   # Compile optimized binary with DWARF stripped (-s -w) to dist/network-tracker.exe
   go build -ldflags="-s -w" -o dist/network-tracker.exe ./cmd/tracker
   ```

2. **Test Windows Service mode:**
   ```powershell
   # Install service into Windows SCM (Run PowerShell as Administrator)
   .\dist\network-tracker.exe service install

   # Start service
   .\dist\network-tracker.exe service start

   # Check status
   .\dist\network-tracker.exe service status

   # Stop service
   .\dist\network-tracker.exe service stop

   # Uninstall service
   .\dist\network-tracker.exe service uninstall
   ```

3. **Run 6-stage self-test suite:**
   ```powershell
   .\dist\network-tracker.exe test
   ```

---

### 💡 Key Development Tips for You

1. **Avoid RAM allocations in polling loops (Zero Allocation):**
   - When invoking `GetExtendedTcpTable`, pre-allocate a byte buffer initially (e.g., `buf := make([]byte, 65536)`).
   - Reuse this buffer in subsequent polling iterations instead of making new allocations each time. This keeps runtime RAM stable at **~8MB** indefinitely!
2. **Smooth log file rotation:**
   - Use `time.Now().Format("2006-01-02")` to detect date rollover.
   - When a new day arrives, close existing file handles and open new handles pointing to the new day's folder.
   - Check file size via `file.Stat()`. When `size >= 100 * 1024 * 1024` (100MB), rename to `_1.log` and create a fresh file.
3. **Graceful Shutdown:**
   - Always listen on signal channels `c := make(chan os.Signal, 1)` with `signal.Notify(c, os.Interrupt, syscall.SIGTERM)` so when stopped, Go flushes all pending log records from buffer to disk before cleanly exiting.
