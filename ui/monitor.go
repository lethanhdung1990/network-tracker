package ui

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"network-tracker/internal/anomaly"
	"network-tracker/internal/config"
	"network-tracker/internal/monitor"
	"network-tracker/internal/service"
)

// Standard alert type identifiers
const (
	AlertNone            = "-"
	AlertSuspiciousPath  = "SUSPICIOUS_PATH"
	AlertBlacklistIP     = "BLACKLIST_IP"
	AlertBlacklistDomain = "BLACKLIST_DOMAIN"
	AlertHighBurst       = "HIGH_BURST"
	AlertUnusualPort     = "UNUSUAL_PORT"
	AlertBandwidthSpike  = "BANDWIDTH_SPIKE"
)

// connectionRow holds formatted connection and alert details
type connectionRow struct {
	Timestamp   string
	Event       string
	Protocol    string
	PID         int
	Process     string
	LocalAddr   string
	RemoteAddr  string
	Domain      string
	State       string
	AlertTitle  string
	AlertDetail string
	ProcessPath string
	UploadBps   uint64
	DownloadBps uint64
}

// pagination holds paging information
type pagination struct {
	current int
	perPage int
	total   int
}

// Model represents the Bubble Tea TUI state
type Model struct {
	title            string
	description      string
	cfg              *config.Config
	poller           *monitor.ConnectionPoller
	detector         *anomaly.AnomalyDetector
	items            []connectionRow
	cursor           int
	selectedPID      int
	pagination       pagination
	paused           bool
	alertsCount      int
	quitting         bool
	serviceStatus    string
	serviceActionMsg string
	serviceName      string
	dnsResolver      *monitor.DNSResolver
	cfgFilePath      string
	lastCfgMod       time.Time
}

// tickMsg fires once per second
type tickMsg time.Time

// Lip Gloss styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5A56E0")).
			Padding(0, 1)

	descStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A0A0A0")).
			Italic(true)

	liveBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#50FA7B")).
			Background(lipgloss.Color("#1A3A2A")).
			Padding(0, 1)

	pauseBadgeStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF5555")).
			Background(lipgloss.Color("#3A1A1A")).
			Padding(0, 1)

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#00E5FF"))

	selectedNormalRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#3A3F58")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true)

	alertRowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4D4D")).
			Bold(true)

	selectedAlertRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("#8B0000")).
				Foreground(lipgloss.Color("#FFFFFF")).
				Bold(true)

	boxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#5A56E0")).
			Padding(0, 1)

	normalDetailBoxStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#6272A4")).
				Padding(0, 1)

	alertDetailBoxStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#FF4D4D")).
				Padding(0, 1)

	pageStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F1FA8C")).
			Bold(true)

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	alertBadgeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF3333")).
			Bold(true)

	safeBadgeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#50FA7B"))

	eventAlertStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF3333")).Bold(true)
	eventListenStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F1FA8C"))
	eventEstabStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B"))
	eventNewStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD"))
	eventCloseStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))

	serviceBoxStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7B68EE")).
			Padding(0, 1)

	svcRunningBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#50FA7B")).
			Bold(true)

	svcStoppedBadge = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F1FA8C")).
			Bold(true)

	svcNotInstalledBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF5555")).
				Bold(true)

	svcActionSuccessStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#50FA7B"))

	svcActionErrorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FF5555"))

	svcActionDefaultStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#8BE9FD")).
				Italic(true)
)

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func renderEvent(event string) string {
	padded := fmt.Sprintf("%-7s", event)
	switch event {
	case "ALERT", "BURST":
		return eventAlertStyle.Render(padded)
	case "LISTEN":
		return eventListenStyle.Render(padded)
	case "ESTAB":
		return eventEstabStyle.Render(padded)
	case "NEW", "CONNECT":
		return eventNewStyle.Render(padded)
	case "CLOSE":
		return eventCloseStyle.Render(padded)
	default:
		return padded
	}
}

// StartUI launches the interactive terminal monitor
func StartUI(cfg *config.Config) {
	program := tea.NewProgram(initModel(cfg), tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Printf("Terminal UI error: %v\n", err)
		os.Exit(1)
	}
}

// initModel creates the TUI model, wiring configuration and native Windows pollers
func initModel(cfg *config.Config) Model {
	dnsResolver := monitor.NewDNSResolver(cfg.DNS.Enabled, cfg.DNS.CacheSize, cfg.DNS.TimeoutMs)
	lifecycle := monitor.NewLifecycleCache(60 * time.Second)
	bandwidth := monitor.NewBandwidthTracker()
	poller := monitor.NewConnectionPoller(cfg, dnsResolver, lifecycle, bandwidth)
	detector := anomaly.NewAnomalyDetector(cfg)

	rowsPerPage := 8
	if cfg != nil && cfg.UI.RowsPerPage > 0 {
		rowsPerPage = cfg.UI.RowsPerPage
	}

	title := strings.ToUpper(service.GetServiceDisplayName(cfg))
	description := service.GetServiceDescription(cfg)
	svcName := service.GetServiceName(cfg)
	svcStatus, _ := service.QueryWindowsServiceStatus(cfg)

	cfgFilePath := config.ResolveConfigPath("config.json")
	var lastCfgMod time.Time
	if info, err := os.Stat(cfgFilePath); err == nil {
		lastCfgMod = info.ModTime()
	}

	m := Model{
		title:            title,
		description:      description,
		cfg:              cfg,
		poller:           poller,
		detector:         detector,
		dnsResolver:      dnsResolver,
		cfgFilePath:      cfgFilePath,
		lastCfgMod:       lastCfgMod,
		cursor:           0,
		selectedPID:      0,
		pagination: pagination{
			current: 1,
			perPage: rowsPerPage,
			total:   0,
		},
		paused:           false,
		alertsCount:      0,
		quitting:         false,
		serviceStatus:    svcStatus,
		serviceActionMsg: "Press [s] Start • [t] Stop • [i] Install • [u] Uninstall • [r] Refresh",
		serviceName:      svcName,
	}

	m.fetchRealConnections()
	return m
}

// fetchRealConnections calls the native poller to retrieve current kernel socket state
func (m *Model) fetchRealConnections() {
	if m.poller == nil || m.detector == nil {
		return
	}

	conns, err := m.poller.Poll()
	if err != nil || len(conns) == 0 {
		return
	}

	rows := make([]connectionRow, 0, len(conns))
	alertCount := 0

	for _, c := range conns {
		alertTitle := AlertNone
		alertDetail := "Process is normal, no violations detected"

		alerts := m.detector.Check(c)
		if len(alerts) > 0 {
			alertTitle = alerts[0].Type
			alertDetail = alerts[0].Message
			alertCount++
		}

		rows = append(rows, connectionRow{
			Timestamp:   c.Timestamp.Format("15:04:05"),
			Event:       c.Event,
			Protocol:    c.Protocol,
			PID:         int(c.PID),
			Process:     c.ProcessName,
			LocalAddr:   fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort),
			RemoteAddr:  fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort),
			Domain:      c.Domain,
			State:       c.State,
			AlertTitle:  alertTitle,
			AlertDetail: alertDetail,
			ProcessPath: c.ProcessPath,
			UploadBps:   c.UploadBps,
			DownloadBps: c.DownloadBps,
		})
	}

	// Stable Sort: Active alerts first -> Process Name -> PID -> Remote Address
	sort.SliceStable(rows, func(i, j int) bool {
		hasAlertI := rows[i].AlertTitle != AlertNone && rows[i].AlertTitle != ""
		hasAlertJ := rows[j].AlertTitle != AlertNone && rows[j].AlertTitle != ""
		if hasAlertI != hasAlertJ {
			return hasAlertI
		}
		if rows[i].Process != rows[j].Process {
			return rows[i].Process < rows[j].Process
		}
		if rows[i].PID != rows[j].PID {
			return rows[i].PID < rows[j].PID
		}
		return rows[i].RemoteAddr < rows[j].RemoteAddr
	})

	m.items = rows
	m.alertsCount = alertCount
	m.pagination.total = len(rows)

	totalPages := (len(rows) + m.pagination.perPage - 1) / m.pagination.perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if m.pagination.current > totalPages {
		m.pagination.current = totalPages
	}
	if m.pagination.current < 1 {
		m.pagination.current = 1
	}

	start := (m.pagination.current - 1) * m.pagination.perPage
	visible := len(rows) - start
	if visible > m.pagination.perPage {
		visible = m.pagination.perPage
	}
	if visible > 0 && m.cursor >= visible {
		m.cursor = visible - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func tickEverySecond() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tickEverySecond()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	totalPages := (len(m.items) + m.pagination.perPage - 1) / m.pagination.perPage
	if totalPages == 0 {
		totalPages = 1
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit

		case " ":
			m.paused = !m.paused

		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			start := (m.pagination.current - 1) * m.pagination.perPage
			visibleCount := len(m.items) - start
			if visibleCount > m.pagination.perPage {
				visibleCount = m.pagination.perPage
			}
			if m.cursor < visibleCount-1 {
				m.cursor++
			}

		case "left", "h":
			if m.pagination.current > 1 {
				m.pagination.current--
				m.cursor = 0
			}

		case "right", "l":
			if m.pagination.current < totalPages {
				m.pagination.current++
				m.cursor = 0
			}

		case "s", "S":
			// Start Windows Service via SCM
			if err := service.StartWindowsService(m.cfg); err != nil {
				m.serviceActionMsg = fmt.Sprintf("[X] Failed to start service: %v (Admin required)", err)
			} else {
				m.serviceActionMsg = fmt.Sprintf("[✔] Windows Service '%s' started successfully!", m.serviceName)
			}
			if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
				m.serviceStatus = status
			}

		case "t", "T":
			// Stop Windows Service via SCM
			if err := service.StopWindowsService(m.cfg); err != nil {
				m.serviceActionMsg = fmt.Sprintf("[X] Failed to stop service: %v (Admin required)", err)
			} else {
				m.serviceActionMsg = fmt.Sprintf("[✔] Windows Service '%s' stopped safely.", m.serviceName)
			}
			if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
				m.serviceStatus = status
			}

		case "i", "I":
			// Install Windows Service (Register with SCM)
			exePath, err := service.GetExecutablePath(m.cfg)
			if err != nil {
				m.serviceActionMsg = fmt.Sprintf("[X] Executable path error: %v", err)
			} else if err := service.InstallService(exePath, m.cfg); err != nil {
				m.serviceActionMsg = fmt.Sprintf("[X] Install failed: %v (Admin required)", err)
			} else {
				m.serviceActionMsg = fmt.Sprintf("[✔] Windows Service '%s' registered with Automatic startup!", m.serviceName)
			}
			if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
				m.serviceStatus = status
			}

		case "u", "U":
			// Uninstall Windows Service (Remove from SCM)
			if err := service.UninstallService(m.cfg); err != nil {
				m.serviceActionMsg = fmt.Sprintf("[X] Uninstall failed: %v (Admin required)", err)
			} else {
				m.serviceActionMsg = fmt.Sprintf("[✔] Windows Service '%s' uninstalled successfully.", m.serviceName)
			}
			if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
				m.serviceStatus = status
			}

		case "r", "R":
			// Refresh Windows Service status
			if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
				m.serviceStatus = status
				m.serviceActionMsg = fmt.Sprintf("[✔] Windows Service status refreshed: %s", status)
			} else {
				m.serviceActionMsg = fmt.Sprintf("[X] Status query error: %v", err)
			}
		}

	case tickMsg:
		if !m.paused {
			m.fetchRealConnections()
		}
		if status, err := service.QueryWindowsServiceStatus(m.cfg); err == nil {
			m.serviceStatus = status
		}
		// 100% Config Hot-Reload watcher
		if modified, newMod := config.CheckModified(m.cfgFilePath, m.lastCfgMod); modified {
			m.lastCfgMod = newMod
			newCfg, err := config.LoadConfig(m.cfgFilePath)
			if err == nil && newCfg != nil {
				m.cfg = newCfg
				m.poller.UpdateConfig(newCfg)
				m.detector.UpdateConfig(newCfg)
				if m.dnsResolver != nil {
					m.dnsResolver.UpdateConfig(newCfg.DNS.Enabled)
				}
				if newCfg.UI.RowsPerPage > 0 {
					m.pagination.perPage = newCfg.UI.RowsPerPage
				}
				m.title = strings.ToUpper(service.GetServiceDisplayName(newCfg))
				m.description = service.GetServiceDescription(newCfg)
				m.serviceName = service.GetServiceName(newCfg)
				m.serviceActionMsg = "[✔] All config parameters reloaded automatically (Hot-Reload)"
			} else if err != nil {
				m.serviceActionMsg = fmt.Sprintf("[!] Config reload syntax error: %v (keeping active config)", err)
			}
		}
		return m, tickEverySecond()
	}

	return m, nil
}

func (m Model) getSelectedItem() *connectionRow {
	start := (m.pagination.current - 1) * m.pagination.perPage
	selectedIdx := start + m.cursor
	if selectedIdx >= 0 && selectedIdx < len(m.items) {
		return &m.items[selectedIdx]
	}
	return nil
}

func (m Model) View() string {
	if m.quitting {
		return "Network Tracker Monitor closed.\n"
	}

	s := "\n"

	statusBadge := liveBadgeStyle.Render("● LIVE (1s)")
	if m.paused {
		statusBadge = pauseBadgeStyle.Render("⏸ PAUSED [PRESS SPACE TO RESUME]")
	}

	alertSummaryBadge := ""
	if m.alertsCount > 0 {
		alertSummaryBadge = lipgloss.NewStyle().
			Background(lipgloss.Color("#FF3333")).
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true).
			Padding(0, 1).
			Render(fmt.Sprintf("🚨 %d ALERTS DETECTED", m.alertsCount))
	} else {
		alertSummaryBadge = lipgloss.NewStyle().
			Background(lipgloss.Color("#1B3B2B")).
			Foreground(lipgloss.Color("#50FA7B")).
			Bold(true).
			Padding(0, 1).
			Render("🛡️ SYSTEM NORMAL")
	}

	titleLine := lipgloss.JoinHorizontal(lipgloss.Center,
		titleStyle.Render(m.title), "  ",
		statusBadge, "  ",
		alertSummaryBadge,
	)
	s += titleLine + "\n"
	s += descStyle.Render(m.description) + "\n\n"

	headerRow := fmt.Sprintf("  %-8s  %-7s  %-5s  %-6s  %-14s  %-21s  %-21s  %-11s  %-15s",
		"TIME", "EVENT", "PROTO", "PID", "PROCESS", "LOCAL ADDR", "REMOTE ADDR", "STATE", "ALERT")
	tableContent := tableHeaderStyle.Render(headerRow) + "\n"
	tableContent += "  " + lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")).Render(strings.Repeat("─", 126)) + "\n"

	start := (m.pagination.current - 1) * m.pagination.perPage
	end := start + m.pagination.perPage
	if end > len(m.items) {
		end = len(m.items)
	}

	if len(m.items) == 0 {
		tableContent += "   Scanning network sockets from Windows Kernel... (Please wait)\n"
	} else {
		for i, item := range m.items[start:end] {
			hasAlert := item.AlertTitle != AlertNone && item.AlertTitle != ""
			isSelected := m.cursor == i
			coloredEvent := renderEvent(item.Event)

			alertColStr := fmt.Sprintf("%-15s", item.AlertTitle)
			if hasAlert {
				alertColStr = alertBadgeStyle.Render(alertColStr)
			} else {
				alertColStr = safeBadgeStyle.Render(alertColStr)
			}

			rowStr := fmt.Sprintf("%-8s  %s  %-5s  %-6d  %-14s  %-21s  %-21s  %-11s  %s",
				item.Timestamp,
				coloredEvent,
				item.Protocol,
				item.PID,
				truncate(item.Process, 14),
				item.LocalAddr,
				item.RemoteAddr,
				item.State,
				alertColStr,
			)

			if isSelected {
				if hasAlert {
					tableContent += selectedAlertRowStyle.Render("👉 "+rowStr) + "\n"
				} else {
					tableContent += selectedNormalRowStyle.Render("👉 "+rowStr) + "\n"
				}
			} else {
				if hasAlert {
					tableContent += alertRowStyle.Render("●  "+rowStr) + "\n"
				} else {
					tableContent += "   " + rowStr + "\n"
				}
			}
		}
	}

	s += boxStyle.Render(tableContent) + "\n"

	selected := m.getSelectedItem()
	if selected != nil {
		hasAlert := selected.AlertTitle != AlertNone && selected.AlertTitle != ""

		detailLines := []string{}
		detailLines = append(detailLines, fmt.Sprintf("📌 PROCESS          : %s (PID: %d)", selected.Process, selected.PID))
		detailLines = append(detailLines, fmt.Sprintf("📁 EXECUTABLE PATH  : %s", selected.ProcessPath))
		detailLines = append(detailLines, fmt.Sprintf("🌐 SOCKET CONNECTION: %s %s -> %s (Domain: %s)", selected.Protocol, selected.LocalAddr, selected.RemoteAddr, selected.Domain))
		detailLines = append(detailLines, fmt.Sprintf("📊 NETWORK METRICS  : %s | Time: %s | Bandwidth: ↑%d B/s  ↓%d B/s", selected.State, selected.Timestamp, selected.UploadBps, selected.DownloadBps))

		detailLines = append(detailLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#444444")).Render(strings.Repeat("─", 80)))

		if hasAlert {
			detailLines = append(detailLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#FF3333")).Bold(true).Render(
				fmt.Sprintf("🚨 ALERT DETECTED    : [%s]", selected.AlertTitle),
			))
			detailLines = append(detailLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#FFAA33")).Bold(true).Render(
				fmt.Sprintf("⚠️  VIOLATION DETAIL : %s", selected.AlertDetail),
			))
			detailLines = append(detailLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#FFDD55")).Italic(true).Render(
				"💡 RECOMMENDATION    : Verify executable authenticity, terminate connection or isolate process!",
			))
			s += alertDetailBoxStyle.Render(strings.Join(detailLines, "\n")) + "\n"
		} else {
			detailLines = append(detailLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Bold(true).Render(
				"🛡️  SECURITY STATUS  : NORMAL (No anomalous behavior detected, valid executable path)",
			))
			s += normalDetailBoxStyle.Render(strings.Join(detailLines, "\n")) + "\n"
		}
	}

	// Windows Service Status & Control Panel
	var statusBadgeStr string
	switch m.serviceStatus {
	case "RUNNING":
		statusBadgeStr = svcRunningBadge.Render("🟢 RUNNING (Background Service 24/7)")
	case "STOPPED":
		statusBadgeStr = svcStoppedBadge.Render("🟡 STOPPED (Installed but inactive)")
	case "NOT_INSTALLED":
		statusBadgeStr = svcNotInstalledBadge.Render("⚪ NOT INSTALLED (Press [i] to install)")
	case "START_PENDING":
		statusBadgeStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD")).Bold(true).Render("🔄 STARTING...")
	case "STOP_PENDING":
		statusBadgeStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB86C")).Bold(true).Render("🔄 STOPPING...")
	default:
		statusBadgeStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render(m.serviceStatus)
	}

	var styledActionMsg string
	if strings.HasPrefix(m.serviceActionMsg, "[✔]") {
		styledActionMsg = svcActionSuccessStyle.Render(m.serviceActionMsg)
	} else if strings.HasPrefix(m.serviceActionMsg, "[X]") {
		styledActionMsg = svcActionErrorStyle.Render(m.serviceActionMsg)
	} else {
		styledActionMsg = svcActionDefaultStyle.Render(m.serviceActionMsg)
	}

	svcLines := []string{
		fmt.Sprintf("⚙️  SERVICE CONTROLLER : %s (%s) | Status: %s", m.serviceName, service.GetServiceDisplayName(m.cfg), statusBadgeStr),
		fmt.Sprintf("💬 ACTION FEEDBACK    : %s", styledActionMsg),
		fmt.Sprintf("⌨️  HOTKEYS            : [s] Start  •  [t] Stop  •  [i] Install  •  [u] Uninstall  •  [r] Refresh"),
	}
	s += serviceBoxStyle.Render(strings.Join(svcLines, "\n")) + "\n"

	totalPages := (len(m.items) + m.pagination.perPage - 1) / m.pagination.perPage
	if totalPages == 0 {
		totalPages = 1
	}
	pageText := fmt.Sprintf(" Page %d/%d (Total: %d connections • Red ●: Active Alert)", m.pagination.current, totalPages, len(m.items))
	s += pageStyle.Render(pageText) + "\n"

	s += footerStyle.Render(" [Space]: Pause/Resume • [↑/↓]: Select • [←/→]: Page • [s]: Start • [t]: Stop • [i]: Install • [u]: Uninstall • [q]: Quit") + "\n"

	return s
}
