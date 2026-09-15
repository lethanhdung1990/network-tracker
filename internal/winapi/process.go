package winapi

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = modKernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = modKernel32.NewProc("QueryFullProcessImageNameW")
	procGetProcessIoCounters      = modKernel32.NewProc("GetProcessIoCounters")
	procCloseHandle               = modKernel32.NewProc("CloseHandle")
)

// GetProcessPath queries the full binary image path for a given process ID
func GetProcessPath(pid uint32) (string, error) {
	// Handle special system process IDs
	if pid == 0 {
		return "[System Idle Process]", nil
	}
	if pid == 4 {
		return "System (ntoskrnl.exe)", nil
	}

	// Open process handle with limited query information rights
	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return "", err
	}
	defer procCloseHandle.Call(handle)

	var buf [1024]uint16
	size := uint32(len(buf))

	ret, _, err := procQueryFullProcessImageName.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", err
	}

	return syscall.UTF16ToString(buf[:size]), nil
}

// GetProcessName extracts the executable filename from a full path
func GetProcessName(path string) string {
	if path == "" {
		return "Unknown"
	}
	if strings.HasPrefix(path, "[") && strings.HasSuffix(path, "]") {
		return path
	}
	base := filepath.Base(path)
	if base == "." || base == "/" || base == "\\" {
		return path
	}
	return base
}

// GetProcessIo retrieves process I/O read/write transfer counters
func GetProcessIo(pid uint32) (IO_COUNTERS, error) {
	if pid == 0 || pid == 4 {
		return IO_COUNTERS{}, nil
	}

	handle, _, err := procOpenProcess.Call(
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return IO_COUNTERS{}, err
	}
	defer procCloseHandle.Call(handle)

	var counters IO_COUNTERS
	ret, _, err := procGetProcessIoCounters.Call(
		handle,
		uintptr(unsafe.Pointer(&counters)),
	)
	if ret == 0 {
		return IO_COUNTERS{}, err
	}

	return counters, nil
}
