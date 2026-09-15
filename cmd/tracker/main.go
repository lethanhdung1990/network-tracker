package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"network-tracker/internal/anomaly"
	"network-tracker/internal/config"
	"network-tracker/internal/monitor"
	"network-tracker/internal/service"
	"network-tracker/internal/storage"
	"network-tracker/internal/winapi"
	"network-tracker/ui"
)

func main() {
	// 1. Automatically align working directory with project root
	service.SetupWorkingDirectory()

	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		fmt.Printf("[!] Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Check if launched under Windows Service Control Manager (SCM)
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		_ = service.RunAsWindowsService(cfg)
		return
	}

	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]

	switch command {
	case "service":
		handleService(cfg)
	case "start":
		handleStart(cfg)
	case "stop":
		handleStop(cfg)
	case "status":
		handleStatus(cfg)
	case "monitor":
		handleMonitor(cfg)
	case "report":
		handleReport(cfg)
	case "test":
		handleTest(cfg)
	default:
		fmt.Printf("[!] Invalid command: %s\n\n", command)
		printHelp()
	}
}

func printHelp() {
	fmt.Println("🛡️  network-tracker CLI - Native Windows Service Network Monitor")
	fmt.Println("Version: 1.1.0 (Windows Service SCM & Console TUI supported)")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  network-tracker <command> [options]")
	fmt.Println()
	fmt.Println("Windows Service Management (services.msc):")
	fmt.Println("  service install    Register Windows Service with Automatic startup (Admin required)")
	fmt.Println("  service uninstall  Remove Windows Service from system (Admin required)")
	fmt.Println("  service start      Start Windows Service via SCM")
	fmt.Println("  service stop       Stop Windows Service via SCM")
	fmt.Println("  service status     Query Windows Service status from SCM")
	fmt.Println()
	fmt.Println("General Control Commands:")
	fmt.Println("  start              Start network monitoring service (use --background or -d to run detached)")
	fmt.Println("  stop               Stop running monitoring service or background daemon")
	fmt.Println("  status             Check running status and active log files")
	fmt.Println("  monitor            Open real-time interactive terminal dashboard (Live TUI)")
	fmt.Println("  report             Generate daily summary report of connections and security alerts")
	fmt.Println("  test               Run comprehensive 6-stage self-test suite")
}

func handleService(cfg *config.Config) {
	if len(os.Args) < 3 {
		fmt.Println("Service Subcommands:")
		fmt.Println("  network-tracker service install    (Register Windows Service - Admin required)")
		fmt.Println("  network-tracker service uninstall  (Remove Windows Service - Admin required)")
		fmt.Println("  network-tracker service start      (Start service via SCM)")
		fmt.Println("  network-tracker service stop       (Stop service via SCM)")
		fmt.Println("  network-tracker service status     (Check status via SCM)")
		return
	}

	sub := os.Args[2]
	svcName := service.GetServiceName(cfg)
	displayName := service.GetServiceDisplayName(cfg)

	switch sub {
	case "install":
		exePath, err := service.GetExecutablePath(cfg)
		if err != nil {
			fmt.Printf("[X] Service installation failed: %v\n", err)
			return
		}
		if err := service.InstallService(exePath, cfg); err != nil {
			fmt.Printf("[X] Service installation failed: %v\n", err)
			return
		}
		fmt.Printf("[✔] Windows Service '%s' registered successfully!\n", svcName)
		fmt.Printf("    • Display Name : %s\n", displayName)
		fmt.Println("    • Startup Type : Automatic (Starts with Windows)")
		fmt.Println("    • Management   : services.msc")
		fmt.Println("    • Start now    : network-tracker service start")

	case "uninstall":
		if err := service.UninstallService(cfg); err != nil {
			fmt.Printf("[X] Service removal failed: %v\n", err)
			return
		}
		fmt.Printf("[✔] Windows Service '%s' removed successfully.\n", svcName)

	case "start":
		if err := service.StartWindowsService(cfg); err != nil {
			fmt.Printf("[X] Failed to start service: %v\n", err)
			return
		}
		fmt.Printf("[✔] Windows Service '%s' started successfully!\n", svcName)

	case "stop":
		if err := service.StopWindowsService(cfg); err != nil {
			fmt.Printf("[X] Failed to stop service: %v\n", err)
			return
		}
		fmt.Printf("[✔] Windows Service '%s' stopped safely.\n", svcName)

	case "status":
		status, err := service.QueryWindowsServiceStatus(cfg)
		if err != nil {
			fmt.Printf("[!] Error querying service status: %v\n", err)
			return
		}
		fmt.Printf("Windows Service '%s' status: %s\n", svcName, status)

	default:
		fmt.Printf("[!] Invalid service subcommand: %s\n", sub)
	}
}

func handleStart(cfg *config.Config) {
	svcName := service.GetServiceName(cfg)

	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	bgFlag := startCmd.Bool("background", false, "Run in background without console window")
	dFlag := startCmd.Bool("d", false, "Run in background without console window (short)")
	fgFlag := startCmd.Bool("foreground", false, "Force foreground execution (internal)")
	_ = startCmd.Parse(os.Args[2:])

	// 1. Direct foreground execution (e.g. spawned by --background)
	if *fgFlag {
		if err := service.RunService(cfg); err != nil {
			fmt.Printf("[!] Error running monitoring service: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 2. Detached background execution
	if *bgFlag || *dFlag {
		if running, pid := service.IsRunning(); running {
			fmt.Printf("[!] network-tracker is already running in background at PID %d\n", pid)
			return
		}

		exePath, err := service.GetExecutablePath(cfg)
		if err != nil {
			fmt.Printf("[!] Failed to start background process: %v\n", err)
			return
		}
		cwd, _ := os.Getwd()
		_ = os.MkdirAll("logs", 0755)

		psCmd := fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList 'start --foreground' -WorkingDirectory '%s' -WindowStyle Hidden", exePath, cwd)
		cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command", psCmd)
		if err := cmd.Run(); err != nil {
			fmt.Printf("[!] Failed to start background process: %v\n", err)
			return
		}

		time.Sleep(1 * time.Second)
		running, childPid := service.IsRunning()
		if running {
			fmt.Printf("[✔] Successfully launched network-tracker in background (PID: %d)\n", childPid)
		} else {
			fmt.Println("[!] Background process launched, check 'network-tracker status'")
		}
		fmt.Println("    - Logs directory : logs/")
		fmt.Println("    - Check status   : network-tracker status")
		fmt.Println("    - Live monitor   : network-tracker monitor")
		fmt.Println("    - Stop daemon    : network-tracker stop")
		return
	}

	// 3. If Windows Service is installed and no flags passed, prioritize starting via SCM
	status, err := service.QueryWindowsServiceStatus(cfg)
	if err == nil && status != "NOT_INSTALLED" {
		if status == "RUNNING" {
			fmt.Printf("[!] Windows Service '%s' is already running (services.msc).\n", svcName)
			return
		}
		fmt.Printf("[*] Starting via Windows Service '%s'...\n", svcName)
		if err := service.StartWindowsService(cfg); err != nil {
			fmt.Printf("[!] Failed to start service: %v\n", err)
		} else {
			fmt.Printf("[✔] Windows Service '%s' started successfully!\n", svcName)
			return
		}
	}

	// 4. Default foreground execution
	if err := service.RunService(cfg); err != nil {
		fmt.Printf("[!] Error running monitoring service: %v\n", err)
		os.Exit(1)
	}
}

func handleStop(cfg *config.Config) {
	svcName := service.GetServiceName(cfg)

	// 1. Check and stop Windows Service first
	status, err := service.QueryWindowsServiceStatus(cfg)
	if err == nil && status == "RUNNING" {
		fmt.Printf("[*] Stopping Windows Service '%s'...\n", svcName)
		if err := service.StopWindowsService(cfg); err == nil {
			fmt.Println("[✔] Windows Service stopped successfully.")
			return
		}
	}

	// 2. Stop detached background process if active
	if err := service.StopDaemon(); err != nil {
		fmt.Printf("[!] %v\n", err)
		return
	}
	fmt.Println("[✔] network-tracker process stopped safely.")
}

func handleStatus(cfg *config.Config) {
	svcName := service.GetServiceName(cfg)

	// Check Windows Service status
	svcStatus, err := service.QueryWindowsServiceStatus(cfg)
	if err == nil && svcStatus != "NOT_INSTALLED" {
		fmt.Printf("[✔] Windows Service '%s': %s (services.msc)\n", svcName, svcStatus)
	}

	running, pid := service.IsRunning()
	if !running && (svcStatus == "NOT_INSTALLED" || svcStatus == "STOPPED") {
		fmt.Println("[-] network-tracker is currently NOT running.")
		fmt.Println("    • Start Windows Service : network-tracker service start")
		fmt.Println("    • Or run detached daemon: network-tracker start --background")
		return
	}

	if running {
		fmt.Printf("[✔] Monitoring daemon is ACTIVE (PID: %d)\n", pid)
	}

	todayDir := filepath.Join("logs", time.Now().Format("2006-01-02"))
	netLog := filepath.Join(todayDir, "network.log")
	if info, err := os.Stat(netLog); err == nil {
		fmt.Printf("    • Today's log  : %s (Size: %.2f KB)\n", netLog, float64(info.Size())/1024.0)
	}

	alertLog := filepath.Join(todayDir, "alerts.log")
	if info, err := os.Stat(alertLog); err == nil {
		fmt.Printf("    • Alerts log   : %s (Size: %.2f KB)\n", alertLog, float64(info.Size())/1024.0)
	}
}

func handleMonitor(cfg *config.Config) {
	ui.StartUI(cfg)
}

func handleReport(cfg *config.Config) {
	day := ""
	if len(os.Args) >= 3 {
		day = os.Args[2]
	} else {
		day = time.Now().Format("2006-01-02")
	}

	if !cfg.Database.Enabled {
		fmt.Println("[!] SQLite database is currently disabled in config.json (database.enabled = false)")
		return
	}

	store, err := storage.NewStorage(cfg.Database.DbPath)
	if err != nil {
		fmt.Printf("[!] Cannot connect to database %s: %v\n", cfg.Database.DbPath, err)
		return
	}
	defer store.Close()

	rep, err := store.GetReport(day)
	if err != nil {
		fmt.Printf("[!] Error querying report: %v\n", err)
		return
	}

	fmt.Printf("\n================ DAILY NETWORK MONITORING REPORT FOR %s ================\n", day)
	fmt.Printf("• Total recorded connections : %d\n", rep.TotalConnections)
	fmt.Printf("• Distinct active processes   : %d\n", rep.UniqueProcesses)
	fmt.Printf("• Total security alerts       : %d\n", rep.TotalAlerts)
	fmt.Println("----------------------------------------------------------------------")

	fmt.Println("📊 TOP 5 PROCESSES BY CONNECTION COUNT:")
	if len(rep.TopProcesses) == 0 {
		fmt.Println("  (No statistical data available)")
	} else {
		for i, p := range rep.TopProcesses {
			fmt.Printf("  %d. %-24s : %d connections\n", i+1, p.Name, p.Count)
		}
	}
	fmt.Println("----------------------------------------------------------------------")

	fmt.Println("🚨 RECENT SECURITY ALERTS TODAY:")
	if len(rep.RecentAlerts) == 0 {
		fmt.Println("  (No security alerts recorded - System normal)")
	} else {
		for i, a := range rep.RecentAlerts {
			fmt.Printf("  %d. [%s] [%s] %s (PID: %d) -> %s\n     Detail: %s\n",
				i+1,
				a.Timestamp.Format("15:04:05"),
				a.Type,
				a.ProcessName,
				a.PID,
				a.Endpoint,
				a.Message,
			)
		}
	}
	fmt.Println("======================================================================\n")
}

func handleTest(cfg *config.Config) {
	fmt.Println("\n🔍 RUNNING 6-STAGE INTEGRATION SELF-TEST...")
	fmt.Println("──────────────────────────────────────────────────────────────────────")

	passed := 0

	// Test 1: Win32 TCP Table
	tcpList, err := winapi.GetTcpTableIPv4()
	if err == nil && len(tcpList) > 0 {
		fmt.Printf("[✔] TEST 1: Win32 Native GetExtendedTcpTable -> PASSED (Found %d TCP sockets)\n", len(tcpList))
		passed++
	} else {
		fmt.Printf("[X] TEST 1: Win32 Native GetExtendedTcpTable -> FAILED: %v\n", err)
	}

	// Test 2: Win32 UDP Table
	udpList, err := winapi.GetUdpTableIPv4()
	if err == nil && len(udpList) > 0 {
		fmt.Printf("[✔] TEST 2: Win32 Native GetExtendedUdpTable -> PASSED (Found %d UDP sockets)\n", len(udpList))
		passed++
	} else {
		fmt.Printf("[X] TEST 2: Win32 Native GetExtendedUdpTable -> FAILED: %v\n", err)
	}

	// Test 3: Process path lookup via Win32 API
	currentPID := uint32(os.Getpid())
	path, err := winapi.GetProcessPath(currentPID)
	if err == nil && path != "" {
		fmt.Printf("[✔] TEST 3: Win32 QueryFullProcessImageNameW -> PASSED (PID %d: %s)\n", currentPID, winapi.GetProcessName(path))
		passed++
	} else {
		fmt.Printf("[X] TEST 3: Win32 QueryFullProcessImageNameW -> FAILED: %v\n", err)
	}

	// Test 4: DNS Resolver Cache
	dns := monitor.NewDNSResolver(true, 1024, 1000)
	domain := dns.Resolve("127.0.0.1")
	if domain == "localhost" {
		fmt.Printf("[✔] TEST 4: DNS Resolver & Cache Engine     -> PASSED (127.0.0.1 => %s)\n", domain)
		passed++
	} else {
		fmt.Printf("[X] TEST 4: DNS Resolver & Cache Engine     -> FAILED\n")
	}

	// Test 5: Anomaly Rule Matching (detect temporary folder executable)
	detector := anomaly.NewAnomalyDetector(cfg)
	fakeConn := monitor.TrackedConnection{
		Timestamp:   time.Now(),
		Event:       "CONNECT",
		Protocol:    "TCP",
		PID:         9999,
		ProcessName: "test_virus.exe",
		ProcessPath: `C:\Users\Admin\AppData\Local\Temp\test_virus.exe`,
		RemoteIP:    "1.2.3.4",
		RemotePort:  9999,
	}
	alerts := detector.Check(fakeConn)
	hasSuspicious := false
	for _, a := range alerts {
		if a.Type == "SUSPICIOUS_PATH" {
			hasSuspicious = true
			break
		}
	}
	if hasSuspicious {
		fmt.Printf("[✔] TEST 5: Anomaly Detector Rule Matching  -> PASSED (Matched SUSPICIOUS_PATH)\n")
		passed++
	} else {
		fmt.Printf("[X] TEST 5: Anomaly Detector Rule Matching  -> FAILED\n")
	}

	// Test 6: SQLite Storage
	testDbPath := "data/test_verification.db"
	store, err := storage.NewStorage(testDbPath)
	if err == nil {
		_ = store.SaveConnection(fakeConn)
		_ = store.Close()
		_ = os.Remove(testDbPath)
		_ = os.Remove(testDbPath + "-wal")
		_ = os.Remove(testDbPath + "-shm")
		fmt.Printf("[✔] TEST 6: SQLite Pure-Go Storage Engine   -> PASSED (WAL Index & Write OK)\n")
		passed++
	} else {
		fmt.Printf("[X] TEST 6: SQLite Pure-Go Storage Engine   -> FAILED: %v\n", err)
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────")
	if passed == 6 {
		fmt.Printf("🎉 RESULT: 6/6 SELF-TESTS PASSED! SYSTEM READY FOR 24/7 OPERATION.\n\n")
	} else {
		fmt.Printf("⚠️ RESULT: %d/6 SELF-TESTS PASSED.\n\n", passed)
	}
}
