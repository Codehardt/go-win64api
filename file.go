//+build windows

package win64api

import (
	"fmt"
	"unsafe"

	so "github.com/Codehardt/go-win64api/shared"
)

var fiNetFileEnum = modNetapi32.NewProc("NetFileEnum")

const FILE_MAX_PREFERRED_LENGTH = 0xFFFFFFFF

type FILE_INFO_3 struct {
	Fi2_id          uint32
	Fi2_permissions uint32
	Fi2_num_locks   uint32
	Fi2_pathname    *uint16
	Fi2_username    *uint16
}

func ListOpenFiles() ([]so.OpenFile, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     FILE_INFO_3
		retVal       = make([]so.OpenFile, 0)
	)
	ret, _, _ := fiNetFileEnum.Call(
		uintptr(0),         // servername
		uintptr(0),         // basename
		uintptr(0),         // username
		uintptr(uint32(3)), // FILE_INFO_3
		uintptr(unsafe.Pointer(&dataPointer)),
		uintptr(uint32(FILE_MAX_PREFERRED_LENGTH)),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NET_API_STATUS_NERR_Success {
		return nil, fmt.Errorf("error fetching open files")
	} else if dataPointer == uintptr(0) {
		return nil, fmt.Errorf("null poinnter while fetching entry")
	}
	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*FILE_INFO_3)(unsafe.Pointer(iter))
		sd := so.OpenFile{
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
