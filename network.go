// +build windows

package winapi

import (
	"fmt"
	"unsafe"

	so "github.com/Codehardt/go-win64api/shared"
)

var shNetShareEnum = modNetapi32.NewProc("NetShareEnum")
var fiNetFileEnum = modNetapi32.NewProc("NetFileEnum")

const SHARE_MAX_PREFERRED_LENGTH = 0xFFFFFFFF
const FILE_MAX_PREFERRED_LENGTH = 0xFFFFFFFF

type SHARE_INFO_2 struct {
	Shi2_netname      *uint16
	Shi2_type         uint32
	Shi2_remark       *uint16
	Shi2_permissions  uint32
	Shi2_max_uses     uint32
	Shi2_current_uses uint32
	Shi2_path         *uint16
	Shi2_passwd       *uint16
}

type FILE_INFO_3 struct {
	Fi2_id          uint32
	Fi2_permissions uint32
	Fi2_num_locks   uint32
	Fi2_pathname    *uint16
	Fi2_username    *uint16
}

func ListNetworkFiles() ([]so.NetworkFile, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     FILE_INFO_3
		retVal       = make([]so.NetworkFile, 0)
	)
	ret, _, _ := fiNetFileEnum.Call(
		uintptr(0),
		uintptr(uint32(3)), // FILE_INFO_3
		uintptr(unsafe.Pointer(&dataPointer)),
		uintptr(uint32(FILE_MAX_PREFERRED_LENGTH)),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NET_API_STATUS_NERR_Success {
		return nil, fmt.Errorf("error fetching network files")
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null poinnter while fetching entry")
	}
	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*FILE_INFO_3)(unsafe.Pointer(iter))
		sd := so.NetworkFile{
			ID:          data.Fi2_id,
			Permissions: data.Fi2_permissions,
			NumLocks:    data.Fi2_num_locks,
			Pathname:    UTF16toString(data.Fi2_pathname),
			Username:    UTF16toString(data.Fi2_username),
		}
		retVal = append(retVal, sd)
		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}
	usrNetApiBufferFree.Call(dataPointer)
	return retVal, nil
}

func ListNetworkShares() ([]so.NetworkShare, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     SHARE_INFO_2
		retVal       = make([]so.NetworkShare, 0)
	)
	ret, _, _ := shNetShareEnum.Call(
		uintptr(0),
		uintptr(uint32(2)), // SHARE_INFO_2
		uintptr(unsafe.Pointer(&dataPointer)),
		uintptr(uint32(SHARE_MAX_PREFERRED_LENGTH)),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NET_API_STATUS_NERR_Success {
		return nil, fmt.Errorf("error fetching network shares")
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null poinnter while fetching entry")
	}
	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*SHARE_INFO_2)(unsafe.Pointer(iter))
		sd := so.NetworkShare{
			Name:        UTF16toString(data.Shi2_netname),
			Comment:     UTF16toString(data.Shi2_remark),
			Permissions: data.Shi2_permissions,
			MaxUses:     data.Shi2_max_uses,
			CurrentUses: data.Shi2_current_uses,
			Path:        UTF16toString(data.Shi2_path),
		}
		retVal = append(retVal, sd)
		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}
	usrNetApiBufferFree.Call(dataPointer)
	return retVal, nil
}
