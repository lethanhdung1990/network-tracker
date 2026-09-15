package winapi

import (
	"encoding/binary"
	"net"
)

// MIB_TCPROW_OWNER_PID represents a Win32 IPv4 TCP table row with owning PID
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID represents a Win32 IPv4 UDP table row with owning PID
type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// IO_COUNTERS holds process I/O accounting metrics from kernel32
type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// SocketInfo represents normalized socket connection metadata
type SocketInfo struct {
	Protocol   string
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
	PID        uint32
}

// Win32 API constants
const (
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1

	AF_INET  = 2  // IPv4
	AF_INET6 = 23 // IPv6

	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_VM_READ                   = 0x0010
)

// TcpStateMap maps Windows TCP status codes to human-readable strings
var TcpStateMap = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTENING",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// ParseIPv4 converts little-endian uint32 from Win32 API into standard IPv4 string
func ParseIPv4(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}

// ParsePort converts network byte order (Big-Endian) port into integer
func ParsePort(port uint32) int {
	return int(binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)}))
}
