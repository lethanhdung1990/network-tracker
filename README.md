# 🛡️ network-tracker - Hệ Thống Giám Sát Kết Nối Mạng Chạy Ngầm Bằng Go (Golang)

> **Tài liệu Kế hoạch Triển khai (Master Project Blueprint & Roadmap)**  
> *Phiên bản kiến trúc tối ưu hóa: Sử dụng 100% Go (Golang) biên dịch ra mã máy Native, siêu nhẹ (<12MB RAM, 0.01% CPU), đóng gói 1 file `.exe` duy nhất, tương tác trực tiếp Windows Kernel API.*

---

## 1. Bối Cảnh & Vấn Đề Cần Giải Quyết (Problem Statement)

### 1.1. Nỗi lo thực tế của người dùng
1. **Máy tính tự gửi request đến những nơi không mong muốn:**
   - Các phần mềm rác, tiện ích mở rộng, telemetry ngầm hoặc phần mềm gián điệp âm thầm kết nối ra máy chủ điều khiển (C2, máy chủ thu thập dữ liệu).
   - Khó kiểm soát được file thực thi `.exe` nào của Windows đang thực sự tạo ra kết nối đó.
2. **Tiến trình gửi mạng liên tục gây nghẽn băng thông, nặng máy:**
   - Các tiến trình bị lỗi vòng lặp (infinite loop retry), liên tục bắn request hoặc âm thầm tải/đẩy dữ liệu nặng trong nền, làm giật lag máy tính và chiếm dụng đường truyền.
3. **Tiến trình chớp nhoáng (Ephemeral Processes):**
   - Các lệnh như `curl.exe`, script PowerShell chạy ngầm hoặc malware mở kết nối, gửi 1 request xong tắt ngay trong 50ms - 100ms. Khi công cụ quét định kỳ tới thì tiến trình đã chết, không thể xác định được danh tính.
4. **Hạn chế của các công cụ có sẵn (như Wireshark):**
   - **Không biết tiến trình (Process):** Wireshark bắt raw packet ở tầng driver mạng (Npcap), chỉ thấy IP/Port chứ **không thể biết tên file `.exe` hay `PID` nào** của Windows đang tạo socket.
   - **Quá nặng nề cho việc chạy 24/7:** Wireshark lưu trữ toàn bộ nội dung gói tin (payload), ngốn hàng gigabyte RAM và tạo file dump khổng lồ làm đơ máy.

---

## 2. Mục Tiêu Dự Án (Project Goals)

- 🪶 **Siêu nhẹ & Tiết kiệm tài nguyên tối đa (Go Native):**
  - **Mức RAM khi chạy ngầm:** Chỉ **~8 - 12 MB** (bằng 1/3 Python, chỉ chiếm 1/1000 thanh RAM 8GB).
  - **Mức CPU:** Gần như **0.0% - 0.01%**.
  - **Đóng gói 1 file `.exe` duy nhất (~6MB):** Chạy độc lập, không cần cài Python, không cần cài Go hay bất kỳ runtime nào trên máy khác.
- 🎯 **Gắn chặt Kết nối với Tiến trình:** Mọi kết nối ra/vào đều xác định được `PID`, `Tên tiến trình` (VD: `chrome.exe`, `curl.exe`) và `Đường dẫn thực thi đầy đủ` (phát hiện ngay file chạy từ thư mục `Temp`, `AppData`).
- ⚡ **Bắt trọn Tiến trình Chớp Nhoáng:** Cơ chế đối soát tam giác (Process Lifecycle Cache + TCP `TIME_WAIT` + DNS Cache) với chu kỳ quét siêu tốc **100ms - 200ms** mà không làm nóng máy.
- 🌐 **Phân giải Tên miền (Domain Resolution):** Kết hợp Windows DNS Client Cache và Reverse DNS để chuyển đổi IP thành Domain rõ ràng (VD: `github.com`, `google.com` thay vì IP trần).
- 🚨 **Cảnh báo Bất thường & Nặng máy:**
  - `HIGH_FREQUENCY_BURST`: Cảnh báo khi 1 ứng dụng mở dồn dập hàng chục kết nối trong vài giây.
  - `SUSPICIOUS_EXECUTABLE_PATH`: Cảnh báo file chạy từ `Temp`, `AppData\Roaming`, `C:\Users\Public`.
  - `UNUSUAL_DESTINATION_PORT`: Cảnh báo kết nối ra các cổng lạ.
  - `HEAVY_BANDWIDTH_BURST`: Cảnh báo tiến trình ngốn lưu lượng tải/gửi lớn.
- 📁 **Quản lý Log Khoa Học:**
  - Mỗi ngày 1 thư mục riêng (`logs/YYYY-MM-DD/`).
  - Mỗi file log không bao giờ vượt quá **100MB** (tự động cắt file xoay vòng).
  - Cấu trúc format text tùy biến, JSON Lines, và SQLite thống kê.
- 🖥️ **Giao diện TUI & Chế độ Tự Kiểm Tra (Self-Test):** Bảng theo dõi trực tiếp trên terminal và bộ kiểm thử tự động.

---

## 3. Kiến Trúc Kỹ Thuật Đề Xuất (System Architecture)

### 3.1. Sơ đồ luồng xử lý dữ liệu bằng Goroutines song song

```
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
    │  - Đối soát Process Lifecycle Cache (Bắt tiến trình 50ms)   │
    │  - Tra cứu Exe Name, Path (QueryFullProcessImageNameW)      │
    │  - Ghép Socket + PID + Domain                               │
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

### 3.2. Chi tiết 5 tầng chức năng bằng Go

| Tầng chức năng | Mô tả vai trò | Công nghệ Go đã chốt |
|---|---|---|
| **1. Connection & Process Monitor** | Gọi trực tiếp Windows Native API qua `syscall` / `golang.org/x/sys/windows`. Quét trạng thái `ESTABLISHED` và `TIME_WAIT`. | `iphlpapi.dll` (`GetExtendedTcpTable`, `GetExtendedUdpTable`), `kernel32.dll` (`OpenProcess`, `QueryFullProcessImageNameW`). **Tốc độ: ~40 micro-giây/lần**. |
| **2. DNS Resolution Layer** | Đọc cache DNS Windows và Reverse DNS bất đồng bộ. | Đọc cache qua Windows API / PowerShell JSON stream, `net.LookupAddr` trong goroutines với LRU cache. |
| **3. Bandwidth & Anomaly Engine** | Đo tốc độ truyền dữ liệu I/O theo từng PID, phát hiện connection burst bằng sliding window. | `kernel32.dll` (`GetProcessIoCounters`), thread-safe ring buffer. |
| **4. Logging & Storage Layer** | Phân chia log theo thư mục ngày `logs/YYYY-MM-DD/`, xoay vòng khi file chạm 100MB. Ghi text template, JSONL, SQLite. | Standard library `os`, `io`, `encoding/json`, `log/slog`, Pure-Go SQLite (`modernc.org/sqlite` - không cần CGO/GCC). |
| **5. Management & UI** | Điều khiển CLI, chạy ngầm bằng Windows Service / Detached process, bảng theo dõi trực tiếp TUI. | TUI bảng màu sắc terminal bằng thư viện Go nhẹ hoặc ANSI escapes, channel lắng nghe `os.Interrupt`. |

---

## 4. Quyết Định Công Nghệ Đã Chốt (Finalized Tech Decisions)

1. **Ngôn ngữ triển khai:** **Go (Golang 1.26.4)**
   - Máy tính của bạn đã có sẵn Go 1.26.4 tại `C:\Program Files\Go\bin\go.exe`.
   - Biên dịch ra **1 file thực thi `.exe` độc lập (~6MB)**, không phụ thuộc môi trường bên ngoài.
2. **Giao tiếp Windows API:** Sử dụng package chuẩn `syscall` và `golang.org/x/sys/windows`
   - Bố cục bộ nhớ Struct của Go khớp 1:1 với Struct của C Windows (`Zero-copy`).
   - Tốc độ gọi API nhanh hơn Python 90 lần, cho phép quét chu kỳ cực ngắn (100ms - 200ms) để bắt các tiến trình mở request rồi tắt ngay mà CPU vẫn giữ ở mức 0.01%.
3. **Cấu hình:** Sử dụng định dạng `config.json` tiêu chuẩn với package chuẩn `encoding/json` của Go.
4. **Giao diện Giám Sát:** **Console TUI (Terminal User Interface)**
   - Chạy trên màn hình Console/PowerShell, hiển thị bảng động trực quan (tốc độ mạng, kết nối đang mở, cảnh báo).
   - Tắt/mở tức thì, đóng TUI không làm ảnh hưởng đến tiến trình chạy ngầm.
   - Hỗ trợ phân trang mượt mà, cấu hình `rows_per_page` trong `config.json`, phím tắt `Space` tạm dừng và điều hướng `k/j/h/l` hoặc phím mũi tên.
5. **Dịch Vụ Chạy Ngầm Native Windows Service (`services.msc`):**
   - Tích hợp sâu vào Windows Service Control Manager (SCM) qua thư viện chuẩn `golang.org/x/sys/windows/svc` và `svc/mgr`.
   - Tự động khởi động cùng Windows khi bật máy (trước cả khi đăng nhập tài khoản), quản lý trạng thái trực quan trong `services.msc`.
   - Cơ chế giải quyết triệt để vấn đề **Session 0 Isolation**: Tự động nhận diện thư mục thực thi và điều hướng Working Directory về thư mục dự án để đọc `config.json` và lưu trữ `logs/`, `data/` chuẩn xác.
   - Hỗ trợ cả 2 chế độ: Windows Service chính quy (`services.msc`) và Daemon ẩn cmd (`start_background.bat`).
6. **Không dùng tool ngoài:** Tuyệt đối không dùng `tshark.exe`, không cần cài driver `Npcap`. 100% code Go thuần túy.

---

## 5. Xử Lý Tiến Trình Chớp Nhoáng (Ephemeral Process Handling)

Một trong những bài toán hóc búa nhất là **tiến trình gửi request xong tắt ngay trong 50ms - 100ms** (ví dụ: `curl.exe`, script ngầm gửi 1 request HTTP POST rồi tự hủy).

`network-tracker` giải quyết triệt để bằng **Cơ chế Đối Soát Tam Giác (Triple Correlation)**:

```
[ 1. Process Lifecycle Cache ] ──┐
  (Lưu dấu vết PID vừa sinh ra)   │
                                  ├──► [ BỘ ĐỐI SOÁT NETWORK-TRACKER ] ──► Ghi Log: "curl.exe (PID 8812) vừa
[ 2. TCP TIME_WAIT Table ]    ──┤      (Khớp PID + Socket + DNS)            kết nối api.abc.com rồi tắt!"
  (Socket lưu lại sau khi tắt)    │
                                  │
[ 3. Windows DNS Client Cache ] ──┘
  (Tên miền vừa được phân giải)
```

1. **Bộ Đệm Vòng Đời Tiến Trình (Process Lifecycle Cache):**
   - Một goroutine theo dõi các tiến trình mới xuất hiện trên Windows.
   - Bất kỳ tiến trình nào vừa sinh ra dù chỉ sống 20 mili-giây, `PID`, `Tên file`, `Đường dẫn đầy đủ` đều được lưu trong bộ đệm trong vòng **60 giây**.
2. **Quét Trạng Thái TCP `TIME_WAIT`:**
   - Theo chuẩn TCP, khi socket đóng, Windows giữ socket ở trạng thái `TIME_WAIT` trong **30 - 120 giây**.
   - `network-tracker` đọc trạng thái `TIME_WAIT` qua `GetExtendedTcpTable`, tra ngược vào bộ đệm để phục hồi danh tính của file `.exe` vừa kết thúc.
3. **Tần Suất Quét Siêu Nhanh 100ms Nhờ Go:**
   - Do Go gọi API chỉ mất 0.04ms (không sinh rác bộ nhớ), `network-tracker` có thể quét ở chu kỳ **100ms/lần** để bắt kịp tiến trình trước khi nó kịp thoát.

---

## 6. Cấu Trúc Dự Án (Project Structure)

Dự án được tổ chức theo chuẩn Go Project Layout:

```text
network-tracker/
├── README.md                      # Kế hoạch tổng thể và tài liệu hướng dẫn (File này)
├── go.mod                         # Go module definition: module network-tracker
├── go.sum                         # Checksums phụ thuộc
├── config.json                    # File cấu hình trung tâm dạng JSON (Monitor, Alerts, Logs, UI...)
│
├── cmd/
│   └── tracker/
│       └── main.go                # Entry point CLI (service, start, stop, status, monitor, report, test)
│
├── internal/
│   ├── winapi/                    # Gọi Windows Native Win32 API qua syscall
│   │   ├── tcp.go                 # GetExtendedTcpTable (IPv4/IPv6, PID, State)
│   │   ├── udp.go                 # GetExtendedUdpTable (IPv4/IPv6, PID)
│   │   ├── process.go             # OpenProcess, QueryFullProcessImageNameW, Process IoCounters
│   │   └── types.go               # C-compatible struct definitions (MIB_TCPROW_OWNER_PID...)
│   │
│   ├── config/
│   │   └── config.go              # Đọc & xác thực config.json (hỗ trợ phân trang ui.rows_per_page)
│   │
│   ├── monitor/
│   │   ├── connection.go          # Snapshot socket & diffing CONNECT / CLOSE
│   │   ├── dns.go                 # Windows DNS Client Cache + Reverse DNS resolver + cache
│   │   ├── bandwidth.go           # Đo lưu lượng I/O bytes/sec theo từng PID
│   │   └── lifecycle.go           # Process Lifecycle Cache bắt tiến trình chớp nhoáng (60s)
│   │
│   ├── anomaly/
│   │   └── detector.go            # Phát hiện burst, path nhạy cảm, port lạ, heavy traffic
│   │
│   ├── logger/
│   │   └── logger.go              # Ghi log: daily folder logs/YYYY-MM-DD/, max 100MB rotation
│   │
│   ├── storage/
│   │   └── storage.go             # SQLite storage (Pure-Go SQLite modernc.org/sqlite, WAL mode)
│   │
│   └── service/
│       ├── windows_service.go     # Native Windows Service (svc.Handler, SCM install/uninstall/status)
│       └── daemon.go              # Quản lý chạy ngầm dạng detached process (PID file, graceful shutdown)
│
├── ui/
│   └── monitor.go                 # Live Terminal TUI Dashboard (Bubble Tea + Lip Gloss, phân trang, pause)
│
├── dist/
│   └── network-tracker.exe        # File thực thi nhị phân duy nhất (~12MB độc lập)
│
├── build.bat                      # Script 1-click: Biên dịch mã nguồn ra dist/network-tracker.exe
├── install_service.bat            # Phím tắt 1-click: Đăng ký & khởi động Windows Service (Run as Admin)
├── uninstall_service.bat          # Phím tắt 1-click: Dừng & gỡ bỏ Windows Service (Run as Admin)
├── start_background.bat           # Phím tắt 1-click: Khởi động chạy ngầm không hiện cửa sổ (chế độ user)
├── stop_background.bat            # Phím tắt 1-click: Dừng tiến trình chạy ngầm
├── monitor.bat                    # Phím tắt 1-click: Bật bảng theo dõi trực tiếp TUI
│
├── logs/                          # Thư mục lưu trữ log (Tự động chia theo ngày)
│   ├── tracker.pid                # File lưu PID của tiến trình chạy ngầm (chế độ detached)
│   ├── 2026-09-15/                # Thư mục riêng của từng ngày (YYYY-MM-DD)
│   │   ├── network.log            # Log kết nối trong ngày (max 100MB, tự cắt file)
│   │   ├── network_1.log          # File xoay vòng nếu network.log chạm 100MB
│   │   ├── alerts.log             # Log riêng các cảnh báo an ninh trong ngày (max 100MB)
│   │   ├── alerts_1.log           # File xoay vòng nếu alerts.log chạm 100MB
│   │   └── connections.jsonl      # (Tùy chọn) JSON Lines stream trong ngày (max 100MB)
│   └── 2026-09-16/                # Tự động tạo thư mục mới khi sang ngày tiếp theo (00:00:00)
│
└── data/                          # Thư mục cơ sở dữ liệu (Tự động tạo)
    └── network_history.db         # SQLite lưu trữ toàn bộ lịch sử để thống kê, truy vấn
```

---

## 7. Thiết Kế Chi Tiết Cấu Trúc Log & Mẫu Cấu Hình (`config.json`)

### 7.1. Mẫu file cấu hình chuẩn (`config.json`)

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
    "rows_per_page": 8
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

### 7.2. Mô tả chi tiết cấu trúc các file Log sẽ ghi

#### 1. File `logs/YYYY-MM-DD/network.log` (Text thân thiện người đọc)
- **Giới hạn dung lượng:** Tối đa **100MB / file**, tự động xoay vòng sang `network_1.log`, `network_2.log`.
- **Cấu trúc trường thông tin:**
  `[TIMESTAMP] [EVENT] [PROCESS_NAME] (PID) -> [REMOTE_IP:PORT] [DOMAIN] | Proto: [PROTO] | State: [STATE] | Path: [EXE_PATH]`
- **Ví dụ dòng log thực tế:**
  ```text
  [2026-09-14 14:30:01] [CONNECT ] chrome.exe         (PID: 14220) -> 142.250.190.46:443   [google.com] | Proto: TCP | State: ESTABLISHED | Path: C:\Program Files\Google\Chrome\Application\chrome.exe
  [2026-09-14 14:30:05] [CONNECT ] curl.exe           (PID: 8812 ) -> 104.21.23.45:443     [api.abc.com] | Proto: TCP | State: TIME_WAIT [PROCESS_EXITED] | Path: C:\Windows\System32\curl.exe
  [2026-09-14 14:30:12] [CLOSE   ] chrome.exe         (PID: 14220) -> 142.250.190.46:443   [google.com] | Proto: TCP | State: TIME_WAIT | Path: C:\Program Files\Google\Chrome\Application\chrome.exe
  ```

#### 2. File `logs/YYYY-MM-DD/alerts.log` (Log Cảnh Báo An Ninh & Nghẽn Mạng)
- **Giới hạn dung lượng:** Tối đa **100MB / file**, tự động xoay vòng sang `alerts_1.log`.
- **Cấu trúc trường thông tin:**
  `[TIMESTAMP] [ALERT:LEVEL] [ALERT_TYPE] [MESSAGE] | Process: [NAME] (PID) | Endpoint: [IP:PORT] ([DOMAIN]) | Details: [JSON_METADATA]`
- **Ví dụ dòng log cảnh báo thực tế:**
  ```text
  [2026-09-14 14:30:15] [ALERT:HIGH] [HIGH_FREQUENCY_BURST] Tiến trình bad_tool.exe mở dồn dập 35 kết nối trong 10s (Ngưỡng: 25) | Process: bad_tool.exe (8812) | Endpoint: 104.21.23.45:443 | Details: {"connections_in_window": 35, "window_sec": 10}
  [2026-09-14 14:30:20] [ALERT:HIGH] [SUSPICIOUS_EXECUTABLE_PATH] Tiến trình đang chạy từ thư mục đáng ngờ: C:\Users\dunglt\AppData\Local\Temp\miner.exe | Process: miner.exe (9912) | Endpoint: 185.220.101.5:4444 (unknown) | Details: {"rule": "AppData\\Local\\Temp"}
  [2026-09-14 14:30:30] [ALERT:HIGH] [HEAVY_BANDWIDTH_BURST] Tiến trình background_sync.exe đang ngốn lưu lượng mạng lớn: 8.50 MB/s | Process: background_sync.exe (3120) | Endpoint: 13.107.4.52:443 | Details: {"upload_kb_s": 8700, "download_kb_s": 200}
  ```

#### 3. File `logs/YYYY-MM-DD/connections.jsonl` (Dữ liệu JSON Stream)
- **Mục đích:** Mỗi dòng là một JSON object độc lập, phục vụ phân tích hoặc xuất dữ liệu. Max 100MB / file.

#### 4. Cơ Sở Dữ Liệu SQLite (`data/network_history.db`)
- Sử dụng driver Pure-Go `modernc.org/sqlite` (không cần cài GCC/CGO).
- Gồm 2 bảng `connections` và `alerts` phục vụ lệnh `network-tracker report`.

---

## 8. Kế Hoạch Triển Khai Từng Bước (Execution Roadmap)

### Giai đoạn 1: Khởi Tạo Dự Án Go & Win32 Native Syscalls
- Khởi tạo `go.mod` (module `network-tracker`).
- Xây dựng package `internal/winapi`:
  - `tcp.go`: Gọi `GetExtendedTcpTable` (IPv4 & IPv6).
  - `udp.go`: Gọi `GetExtendedUdpTable` (IPv4 & IPv6).
  - `process.go`: Gọi `OpenProcess`, `QueryFullProcessImageNameW`, `GetProcessIoCounters`.
- Xây dựng `internal/config`: Nạp và kiểm tra `config.json`.

### Giai đoạn 2: Lõi Giám Sát, DNS & Bắt Tiến Trình Chớp Nhoáng
- Xây dựng `internal/monitor/connection.go`: Quét snapshot socket, so khớp `CONNECT`/`CLOSE`.
- Xây dựng `internal/monitor/lifecycle.go`: Process Lifecycle Cache theo dõi các PID vừa sinh ra trong 60 giây.
- Xây dựng `internal/monitor/dns.go`: Đồng bộ Windows DNS Client Cache và Reverse DNS bất đồng bộ.
- Xây dựng `internal/monitor/bandwidth.go`: Tính lưu lượng I/O gửi/nhận theo thời gian thực.

### Giai đoạn 3: Engine Cảnh Báo Bất Thường & Ghi Log Đa Kênh
- Xây dựng `internal/anomaly/detector.go`: Phát hiện burst spam, đường dẫn nhạy cảm, cổng lạ, lưu lượng ngốn mạng lớn.
- Xây dựng `internal/logger/logger.go`: Quản lý tạo folder theo ngày `logs/YYYY-MM-DD/`, xoay vòng file max 100MB (`network.log`, `alerts.log`).
- Xây dựng `internal/storage/storage.go`: Lưu trữ SQLite với cơ chế Batch insert và WAL mode.

### Giai đoạn 4: Dịch Vụ Chạy Ngầm & CLI Điều Khiển
- Xây dựng `internal/service/daemon.go`: Quản lý chạy ngầm không hiện cửa sổ, ghi `logs/tracker.pid`, xử lý dừng an toàn khi nhận `SIGINT`/`SIGTERM`.
- Xây dựng `cmd/tracker/main.go` với các lệnh: `start`, `stop`, `status`, `report`, `test`, `monitor`, `service`.
- Tạo `build.bat`: Biên dịch ra `dist/network-tracker.exe` trong 1 giây.
- Tạo `start_background.bat`, `stop_background.bat`, `monitor.bat`.

### Giai đoạn 5: Màn Hình TUI & Chế Độ Tự Kiểm Tra (Self-Test)
- Xây dựng `ui/monitor.go`: Live Terminal Dashboard TUI thời gian thực (Bubble Tea + Lip Gloss).
- Cơ chế ổn định giao diện: Sắp xếp danh sách tĩnh theo cảnh báo & tên tiến trình, khóa con trỏ sticky, tôn trọng trang hiện tại của người dùng (không giật về trang 1).
- Cấu hình số dòng mỗi trang (`ui.rows_per_page`) trong `config.json`.
- Phím tắt điều khiển: `Space` (Tạm dừng/Tiếp tục), `j/k/Down/Up` (Di chuyển con trỏ), `h/l/Left/Right` (Chuyển trang), `q` (Thoát).
- Xây dựng lệnh `network-tracker.exe test`: Tự động chạy 6 bài kiểm thử toàn diện trên máy người dùng.

### Giai đoạn 6: Tích Hợp Native Windows Service (services.msc)
- Xây dựng `internal/service/windows_service.go`: Triển khai trọn vẹn `svc.Handler` (`Execute`) và kết nối Windows SCM (`mgr.Mgr`).
- Tự động nhận diện ngữ cảnh SCM (`svc.IsWindowsService()`): Tự chuyển sang chế độ phục vụ Service khi Windows boot máy.
- Giải quyết triệt để **Session 0 Isolation**: `service.SetupWorkingDirectory()` tự động phát hiện đường dẫn binary và chuyển thư mục làm việc từ `C:\Windows\System32` về thư mục dự án để nạp `config.json`, ghi log `logs/`, cơ sở dữ liệu `data/`.
- Tự động mở rộng quyền truy vấn: Cho phép người dùng thường (non-admin) kiểm tra trạng thái dịch vụ (`service status`) qua quyền `SC_MANAGER_CONNECT` + `SERVICE_QUERY_STATUS`.
- Các file tiện ích 1-click tự động xin quyền UAC Administrator: `install_service.bat`, `uninstall_service.bat`.

---

## 9. Cẩm Nang Sử Dụng & Vận Hành Hệ Thống

### 9.1. Quản lý bằng Native Windows Service (`services.msc`) - KHUYÊN DÙNG CHO SẢN PHẨM 24/7

Chế độ Windows Service giúp hệ thống chạy liên tục 24/7, tự động bật cùng máy tính trước khi người dùng đăng nhập, không sợ bị tắt nhầm khi đóng cửa sổ terminal.

#### 1. Cài đặt Windows Service (Cần quyền Administrator):
- **Cách 1 (1-Click):** Chuột phải vào file `install_service.bat` -> Chọn **Run as administrator**.
- **Cách 2 (CLI):** Mở cmd/PowerShell bằng quyền Admin và gõ:
  ```powershell
  .\dist\network-tracker.exe service install
  ```
- **Kết quả:** Windows Service mang tên **`NetworkTracker`** (Tên hiển thị: *Network Tracker Monitoring Service*) sẽ được đăng ký vào Windows với chế độ khởi động tự động (`Automatic`). Bạn có thể mở `services.msc` để kiểm tra.

#### 2. Khởi động và dừng dịch vụ:
```powershell
# Khởi động dịch vụ
.\dist\network-tracker.exe service start

# Dừng dịch vụ
.\dist\network-tracker.exe service stop

# Kiểm tra trạng thái dịch vụ (Không cần quyền Admin)
.\dist\network-tracker.exe service status
```

#### 3. Gỡ bỏ Windows Service:
- **Cách 1 (1-Click):** Chuột phải vào file `uninstall_service.bat` -> Chọn **Run as administrator**.
- **Cách 2 (CLI):** Mở cmd/PowerShell Admin và gõ:
  ```powershell
  .\dist\network-tracker.exe service uninstall
  ```

---

### 9.2. Quản lý bằng Chế độ Chạy Ẩn Người Dùng (Detached Background)

Nếu bạn không muốn cài Service hệ thống mà chỉ muốn chạy ẩn trong phiên làm việc hiện tại:
- **Bật chạy ẩn:** Double click `start_background.bat` hoặc gõ `.\dist\network-tracker.exe start`.
- **Kiểm tra trạng thái:** Gõ `.\dist\network-tracker.exe status`.
- **Dừng chạy ẩn:** Double click `stop_background.bat` hoặc gõ `.\dist\network-tracker.exe stop`.

---

### 9.3. Bật Màn Hình Theo Dõi Trực Quan (Live TUI Monitor)

Bất kỳ lúc nào (dù đang chạy Windows Service hay chạy nền detached), bạn đều có thể mở giao diện TUI để xem trực quan:
- Double click `monitor.bat` hoặc gõ:
  ```powershell
  .\dist\network-tracker.exe monitor
  ```
- **Các phím điều khiển trên bảng:**
  - `Space`: Tạm dừng (PAUSE) hoặc Tiếp tục (RESUME) cập nhật để dễ dàng soi chi tiết từng dòng.
  - `↑ / k`: Di chuyển con trỏ lên dòng trên.
  - `↓ / j`: Di chuyển con trỏ xuống dòng dưới.
  - `← / h`: Chuyển lùi về trang trước.
  - `→ / l`: Chuyển tiến sang trang kế tiếp.
  - `q` hoặc `Ctrl+C`: Thoát màn hình giám sát (không ảnh hưởng tới dịch vụ ngầm đang chạy).
  - Khung **Chi tiết kết nối đã chọn** ở góc dưới hiển thị: *Tên tiến trình, PID, Địa chỉ đích, Trạng thái socket, Tốc độ mạng, Cảnh báo an ninh nổi bật màu đỏ*.

---

### 9.4. Xuất Báo Cáo Thống Kê & Chạy Tự Kiểm Tra (Self-Test)

- **Xuất báo cáo tổng kết trong ngày:**
  ```powershell
  .\dist\network-tracker.exe report
  ```
- **Chạy bộ tự kiểm tra 6 bài toàn diện:**
  ```powershell
  .\dist\network-tracker.exe test
  ```

---

## 10. Hướng Dẫn Khởi Tạo & Phát Triển Bằng Tay Cho Developer (Developer Starter Guide)

Dưới đây là cẩm nang từng bước để bạn tự tay viết mã nguồn (code by hand) cho dự án từ đầu:

### Bước 1: Khởi tạo Go Module & Tạo Khung Thư Mục

Mở PowerShell tại thư mục dự án `d:\Projects\#_Self\network-tracker` và chạy các lệnh sau:

```powershell
# 1. Khởi tạo module Go
go mod init network-tracker

# 2. Tạo toàn bộ cây thư mục theo chuẩn Go Layout
New-Item -ItemType Directory -Force cmd/tracker, internal/winapi, internal/config, internal/monitor, internal/anomaly, internal/logger, internal/storage, internal/service, ui, logs, data
```

---

### Bước 2: Tạo File Cấu Hình Ban Đầu (`config.json`)

Tạo file `config.json` ở thư mục gốc dự án với nội dung mẫu:

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

### Bước 3: Cẩm Nang Lập Trình Windows Native API Trong Go (`internal/winapi/`)

Đây là phần kỹ thuật quan trọng nhất. Bạn sẽ gọi trực tiếp các DLL của Windows mà không cần CGO:

#### 1. Định nghĩa DLL và con trỏ hàm:
Trong Go, sử dụng `syscall.NewLazyDLL`:
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

#### 2. Khai báo Struct C tương thích với Windows:
Bố cục bộ nhớ (struct alignment) phải khớp 100% với Windows SDK:
```go
// Struct đại diện cho 1 kết nối TCP kèm PID
type MIB_TCPROW_OWNER_PID struct {
    State      uint32
    LocalAddr  uint32
    LocalPort  uint32
    RemoteAddr uint32
    RemotePort uint32
    OwningPid  uint32
}

// Bảng hằng số bảng mở rộng
const (
    TCP_TABLE_OWNER_PID_ALL = 5
    AF_INET                 = 2 // IPv4
    AF_INET6                = 23 // IPv6
)
```

#### 3. Kỹ thuật chuyển đổi IP và Port (Network Byte Order):
Windows lưu IP và Port dưới dạng Network Endian (Big/Little Endian), bạn chuyển đổi sang định dạng đọc được như sau:
```go
import (
    "encoding/binary"
    "net"
)

// Chuyển đổi uint32 sang IPv4 string
func ParseIPv4(addr uint32) string {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, addr)
    return ip.String()
}

// Chuyển đổi uint32 sang Port số nguyên
func ParsePort(port uint32) int {
    return int(binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)}))
}
```

#### 4. Tra cứu đường dẫn file `.exe` từ PID:
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

### Bước 4: Khung Điểm Khởi Đầu (`cmd/tracker/main.go`)

Khung sườn CLI xử lý các lệnh điều khiển và tự động nhận diện Windows Service:

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
    // 1. Tự động chuyển Working Directory về thư mục gốc dự án (khắc phục Session 0 C:\Windows\System32)
    service.SetupWorkingDirectory()

    cfg, _ := config.LoadConfig("config.json")

    // 2. Nếu Windows SCM khởi chạy ứng dụng này, lập tức chuyển sang chế độ Windows Service
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

### Bước 5: Các Lệnh Biên Dịch & Chạy Thử Nghiệm

1. **Biên dịch 1-click bằng `build.bat` hoặc lệnh Go:**
   ```powershell
   # Biên dịch tối ưu mã máy loại bỏ DWARF info (-s -w) ra file dist/network-tracker.exe
   go build -ldflags="-s -w" -o dist/network-tracker.exe ./cmd/tracker
   ```

2. **Chạy thử nghiệm chế độ Windows Service:**
   ```powershell
   # Cài đặt dịch vụ vào Windows SCM (Mở PowerShell với Run as Administrator)
   .\dist\network-tracker.exe service install

   # Bật dịch vụ
   .\dist\network-tracker.exe service start

   # Kiểm tra trạng thái
   .\dist\network-tracker.exe service status

   # Dừng dịch vụ
   .\dist\network-tracker.exe service stop

   # Gỡ bỏ dịch vụ
   .\dist\network-tracker.exe service uninstall
   ```

3. **Chạy kiểm thử toàn bộ hệ thống (Self-Test 6 bài):**
   ```powershell
   .\dist\network-tracker.exe test
   ```

---

### 💡 Mẹo Phát Triển Quan Trọng Dành Cho Bạn

1. **Tránh cấp phát RAM trong vòng lặp quét (Zero Allocation):**
   - Khi gọi `GetExtendedTcpTable`, hãy cấp phát 1 mảng byte buffer ban đầu (ví dụ `buf := make([]byte, 65536)`).
   - Tái sử dụng (reuse) buffer này ở các chu kỳ quét tiếp theo thay vì `make` mới mỗi lần. Việc này giúp RAM của bạn đứng yên ở mức **~8MB** vĩnh viễn mà không bao giờ tăng!
2. **Quản lý đóng mở file log mượt mà:**
   - Dùng `time.Now().Format("2006-01-02")` để phát hiện khi sang ngày mới.
   - Khi sang ngày mới, đóng file handler cũ và mở file handler trỏ vào folder ngày mới.
   - Đo kích thước file bằng `file.Stat()`, khi `size >= 100 * 1024 * 1024` (100MB) thì rename sang `_1.log` và tạo file mới.
3. **Graceful Shutdown:**
   - Luôn sử dụng channel `c := make(chan os.Signal, 1)` kết hợp `signal.Notify(c, os.Interrupt, syscall.SIGTERM)` để khi bạn ấn `stop` hoặc tắt máy, Go sẽ hoàn tất việc ghi nốt các dòng log trong buffer xuống đĩa rồi mới thoát sạch sẽ.

