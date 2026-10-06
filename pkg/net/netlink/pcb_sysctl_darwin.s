#include "textflag.h"

// The trampoline and pointer layout are shared by Darwin arm64 and amd64.
TEXT pcb_sysctl_trampoline<>(SB),NOSPLIT,$0-0
	JMP pcb_libc_sysctl(SB)
GLOBL ·pcbSysctlAddr(SB), RODATA, $8
DATA ·pcbSysctlAddr(SB)/8, $pcb_sysctl_trampoline<>(SB)
