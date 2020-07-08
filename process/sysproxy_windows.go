package process

//http://www.hoverlees.com/blog/?p=1465#more-1465
import (
	"syscall"
	"unsafe"
)

var modwininet = syscall.NewLazyDLL("wininet.dll")
var InternetSetOptionA = modwininet.NewProc("InternetSetOptionA")

type (
	BOOL          uint32
	BOOLEAN       byte
	BYTE          byte
	DWORD         uint32
	DWORD64       uint64
	HANDLE        uintptr
	HLOCAL        uintptr
	LARGE_INTEGER int64
	LONG          int32
	LPVOID        uintptr
	SIZE_T        uintptr
	UINT          uint32
	ULONG_PTR     uintptr
	ULONGLONG     uint64
	WORD          uint16
)

//typedef struct {
//DWORD                       dwSize;
//LPSTR                       pszConnection;
//DWORD                       dwOptionCount;
//DWORD                       dwOptionError;
//LPINTERNET_PER_CONN_OPTIONA pOptions;
//} INTERNET_PER_CONN_OPTION_LISTA, *LPINTERNET_PER_CONN_OPTION_LISTA;

type INTERNET_PER_CONN_OPTION_LISTA struct {
	dwsize        DWORD
	pszConnection *uint16
	dwOptionCount DWORD
	dwOptionError DWORD
	pOptions      []LPINTERNET_PER_CONN_OPTIONA
}

//typedef struct {
//DWORD dwOption;
//union {
//DWORD    dwValue;
//LPSTR    pszValue;
//FILETIME ftValue;
//} Value;
//} INTERNET_PER_CONN_OPTIONA, *LPINTERNET_PER_CONN_OPTIONA;
type LPINTERNET_PER_CONN_OPTIONA struct {
	dwOption DWORD
	value    struct {
		dwValue  DWORD
		pszValue *uint16
		ftValue  FILETIME
	}
}

//typedef struct _FILETIME {
//DWORD dwLowDateTime;
//DWORD dwHighDateTime;
//} FILETIME, *PFILETIME, *LPFILETIME;

type FILETIME struct {
	dwLowDateTime  DWORD
	dwHighDateTime DWORD
}

func setSysProxy() {
	//syscall.StringToUTF16Ptr()
	list := INTERNET_PER_CONN_OPTION_LISTA{}
	list.dwsize = (DWORD)(unsafe.Sizeof(list))
	list.pszConnection = nil
}
func unsetSysProxy() {}
