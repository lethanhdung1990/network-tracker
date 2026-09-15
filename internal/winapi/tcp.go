package winapi

import (
	"syscall"
	"unsafe"
)

var (
	modIphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	ERROR_INSUFFICIENT_BUFFER = 122
	NO_ERROR                  = 0
)

// GetTcpTableIPv4 retrieves all active IPv4 TCP sockets with owning PIDs from Windows Kernel
func GetTcpTableIPv4() ([]SocketInfo, error) {
	var size uint32 = 65536 // Initial 64KB buffer allocation to minimize secondary reallocation calls
	buf := make([]byte, size)

	// First call
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE
		uintptr(AF_INET),
		uintptr(TCP_TABLE_OWNER_PID_ALL),
		0,
	)

	// If buffer is insufficient, reallocate with required size and retry
	if ret == uintptr(ERROR_INSUFFICIENT_BUFFER) {
		buf = make([]byte, size)
		ret, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(AF_INET),
			uintptr(TCP_TABLE_OWNER_PID_ALL),
			0,
		)
	}

	if ret != uintptr(NO_ERROR) {
		return nil, syscall.Errno(ret)
	}

	// First 4 bytes contain dwNumEntries
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return []SocketInfo{}, nil
	}

	results := make([]SocketInfo, 0, numEntries)
	rowSize := unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})
	rowsStart := uintptr(unsafe.Pointer(&buf[4]))

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(rowsStart + uintptr(i)*rowSize))

		stateStr := TcpStateMap[row.State]
		if stateStr == "" {
			stateStr = "UNKNOWN"
		}

		results = append(results, SocketInfo{
			Protocol:   "TCP",
			LocalIP:    ParseIPv4(row.LocalAddr),
			LocalPort:  ParsePort(row.LocalPort),
			RemoteIP:   ParseIPv4(row.RemoteAddr),
			RemotePort: ParsePort(row.RemotePort),
			State:      stateStr,
			PID:        row.OwningPid,
		})
	}

	return results, nil
}
