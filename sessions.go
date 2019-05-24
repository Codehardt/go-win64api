// +build windows

package winapi

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	so "github.com/Codehardt/go-win64api/shared"
)

var (
	modSecur32                    = syscall.NewLazyDLL("secur32.dll")
	sessLsaFreeReturnBuffer       = modSecur32.NewProc("LsaFreeReturnBuffer")
	sessLsaEnumerateLogonSessions = modSecur32.NewProc("LsaEnumerateLogonSessions")
	sessLsaGetLogonSessionData    = modSecur32.NewProc("LsaGetLogonSessionData")
	sessNetSessionEnum            = modNetapi32.NewProc("NetSessionEnum")
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   uintptr
	LogonTime             uint64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	buffer        uintptr
}

type SESSION_INFO_2 struct {
	Sesi2_cname       *uint16
	Sesi2_username    *uint16
	Sesi2_num_opens   uint32
	Sesi2_time        uint32
	Sesi2_idle_time   uint32
	Sesi2_user_flags  uint32
	Sesi2_cltype_name *uint16
}

func ListNetworkSessions() ([]so.NetworkSession, error) {
	var (
		dataPointer  uintptr
		resumeHandle uintptr
		entriesRead  uint32
		entriesTotal uint32
		sizeTest     SESSION_INFO_2
		retVal       = make([]so.NetworkSession, 0)
	)
	ret, _, _ := sessNetSessionEnum.Call(
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(uint32(2)), // SESSION_INFO_2
		uintptr(unsafe.Pointer(&dataPointer)),
		uintptr(uint32(USER_MAX_PREFERRED_LENGTH)),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&entriesTotal)),
		uintptr(unsafe.Pointer(&resumeHandle)),
	)
	if ret != NET_API_STATUS_NERR_Success {
		return nil, fmt.Errorf("error fetching network sessions")
	} else if dataPointer == uintptr(0) {
		return nil, nil
	}
	var iter = dataPointer
	for i := uint32(0); i < entriesRead; i++ {
		var data = (*SESSION_INFO_2)(unsafe.Pointer(iter))
		sd := so.NetworkSession{
			Clientname: UTF16toString(data.Sesi2_cname),
			Username:   UTF16toString(data.Sesi2_username),
			NumOpens:   data.Sesi2_num_opens,
			Time:       time.Duration(data.Sesi2_time) * time.Second,
			IdleTime:   time.Duration(data.Sesi2_idle_time) * time.Second,
			UserFlags:  data.Sesi2_user_flags,
			ClientType: UTF16toString(data.Sesi2_cltype_name),
		}
		retVal = append(retVal, sd)
		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
	}
	usrNetApiBufferFree.Call(dataPointer)
	return retVal, nil
}

func ListLoggedInUsers() ([]so.SessionDetails, error) {
	var (
		logonSessionCount uint64
		loginSessionList  uintptr
		sizeTest          LUID
		uList             []string            = make([]string, 0)
		uSessList         []so.SessionDetails = make([]so.SessionDetails, 0)
		PidLUIDList       map[uint32]SessionLUID
	)
	PidLUIDList, err := ProcessLUIDList()
	if err != nil {
		return nil, fmt.Errorf("Error getting process list, %s.", err.Error())
	}

	_, _, _ = sessLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&logonSessionCount)),
		uintptr(unsafe.Pointer(&loginSessionList)),
	)
	defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

	var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))

	for i := uint64(0); i < logonSessionCount; i++ {
		var sessionData uintptr
		_, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
		if sessionData != uintptr(0) {
			var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))

			if data.Sid != uintptr(0) {
				validTypes := []uint32{so.SESS_INTERACTIVE_LOGON, so.SESS_CACHED_INTERACTIVE_LOGON, so.SESS_REMOTE_INTERACTIVE_LOGON}
				if in_array(data.LogonType, validTypes) {
					strLogonDomain := strings.ToUpper(LsatoString(data.LogonDomain))
					if strLogonDomain != "WINDOW MANAGER" && strLogonDomain != "FONT DRIVER HOST" {
						sUser := fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
						sort.Strings(uList)
						i := sort.Search(len(uList), func(i int) bool { return uList[i] >= sUser })
						if !(i < len(uList) && uList[i] == sUser) {
							if uok, isAdmin := luidinmap(&data.LogonId, &PidLUIDList); uok {
								uList = append(uList, sUser)
								ud := so.SessionDetails{
									Username:              LsatoString(data.UserName),
									Domain:                strLogonDomain,
									LocalAdmin:            isAdmin,
									LogonType:             data.LogonType,
									DnsDomainName:         LsatoString(data.DnsDomainName),
									LogonTime:             uint64TimestampToTime(data.LogonTime),
									AuthenticationPackage: LsatoString(data.AuthenticationPackage),
									LogonServer:           LsatoString(data.LogonServer),
									LogonId:               fmt.Sprintf("%x%x", data.LogonId.HighPart, data.LogonId.LowPart),
								}

								hn, _ := os.Hostname()
								if strings.ToUpper(ud.Domain) == strings.ToUpper(hn) {
									ud.LocalUser = true
									if isAdmin, _ := IsLocalUserAdmin(ud.Username); isAdmin {
										ud.LocalAdmin = true
									}
								} else {
									if isAdmin, _ := IsDomainUserAdmin(ud.Username, LsatoString(data.DnsDomainName)); isAdmin {
										ud.LocalAdmin = true
									}
								}
								uSessList = append(uSessList, ud)
							}
						}
					}
				}
			}
		}

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
		_, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
	}

	return uSessList, nil
}

func uint64TimestampToTime(nsec uint64) time.Time {
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return time.Unix(0, int64(nsec))
}

func sessUserLUIDs() (map[LUID]string, error) {
	var (
		logonSessionCount uint64
		loginSessionList  uintptr
		sizeTest          LUID
		uList             map[LUID]string = make(map[LUID]string)
	)

	_, _, _ = sessLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&logonSessionCount)),
		uintptr(unsafe.Pointer(&loginSessionList)),
	)
	defer sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(&loginSessionList)))

	var iter uintptr = uintptr(unsafe.Pointer(loginSessionList))

	for i := uint64(0); i < logonSessionCount; i++ {
		var sessionData uintptr
		_, _, _ = sessLsaGetLogonSessionData.Call(uintptr(iter), uintptr(unsafe.Pointer(&sessionData)))
		if sessionData != uintptr(0) {
			var data *SECURITY_LOGON_SESSION_DATA = (*SECURITY_LOGON_SESSION_DATA)(unsafe.Pointer(sessionData))

			if data.Sid != uintptr(0) {
				uList[data.LogonId] = fmt.Sprintf("%s\\%s", strings.ToUpper(LsatoString(data.LogonDomain)), strings.ToLower(LsatoString(data.UserName)))
			}
		}

		iter = uintptr(unsafe.Pointer(iter + unsafe.Sizeof(sizeTest)))
		_, _, _ = sessLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(sessionData)))
	}

	return uList, nil
}

func luidinmap(needle *LUID, haystack *map[uint32]SessionLUID) (bool, bool) {
	for _, l := range *haystack {
		if reflect.DeepEqual(l.Value, *needle) {
			if l.IsAdmin {
				return true, true
			} else {
				return true, false
			}
		}
	}
	return false, false
}

func LsatoString(p LSA_UNICODE_STRING) string {
	return syscall.UTF16ToString((*[4096]uint16)(unsafe.Pointer(p.buffer))[:p.Length])
}

func in_array(val interface{}, array interface{}) (exists bool) {
	exists = false

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				exists = true
				return
			}
		}
	}

	return
}
