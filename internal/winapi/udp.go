package winapi

import (
	"syscall"
	"unsafe"
)

var (
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

// GetUdpTableIPv4 retrieves all active IPv4 UDP sockets with owning PIDs from Windows Kernel
func GetUdpTableIPv4() ([]SocketInfo, error) {
	var size uint32 = 65536
	buf := make([]byte, size)

	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE
		uintptr(AF_INET),
		uintptr(UDP_TABLE_OWNER_PID),
		0,
	)

	if ret == uintptr(ERROR_INSUFFICIENT_BUFFER) {
		buf = make([]byte, size)
		ret, _, _ = procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(AF_INET),
			uintptr(UDP_TABLE_OWNER_PID),
			0,
		)
	}

	if ret != uintptr(NO_ERROR) {
		return nil, syscall.Errno(ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	if numEntries == 0 {
		return []SocketInfo{}, nil
	}

	results := make([]SocketInfo, 0, numEntries)
	rowSize := unsafe.Sizeof(MIB_UDPROW_OWNER_PID{})
	rowsStart := uintptr(unsafe.Pointer(&buf[4]))

	for i := uint32(0); i < numEntries; i++ {
		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(rowsStart + uintptr(i)*rowSize))

		results = append(results, SocketInfo{
			Protocol:   "UDP",
			LocalIP:    ParseIPv4(row.LocalAddr),
			LocalPort:  ParsePort(row.LocalPort),
			RemoteIP:   "0.0.0.0",
			RemotePort: 0,
			State:      "LISTENING",
			PID:        row.OwningPid,
		})
	}

	return results, nil
}
