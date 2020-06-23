package process

//http://www.hoverlees.com/blog/?p=1465#more-1465
import "syscall"

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
	pszConnection uintptr
	dwOptionCount DWORD
	dwOptionError DWORD
	pOptions      struct {
		dwOption DWORD
		value    struct {
			dwValue  DWORD
			pszValue uintptr
			ftValue  uintptr
		}
	}
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
		pszValue uintptr
		ftValue  uintptr
	}
}

func setSysProxy() {
}
func unsetSysProxy() {}
