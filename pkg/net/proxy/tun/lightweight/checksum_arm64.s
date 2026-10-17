#include "textflag.h"

// ASIMD widens native 16-bit words into two independent 32-bit accumulators.
// The 64 KiB input bound keeps every lane and the horizontal sum below 2^32.
TEXT ·checksumBlocks(SB), NOSPLIT, $0-32
	MOVD b_base+0(FP), R0
	MOVD b_len+8(FP), R1
	VEOR V0.B16, V0.B16, V0.B16
	VEOR V5.B16, V5.B16, V5.B16
loop:
	VLD1.P 64(R0), [V1.H8, V2.H8, V3.H8, V4.H8]
	VUADDW V1.H4, V0.S4, V0.S4
	VUADDW2 V1.H8, V5.S4, V5.S4
	VUADDW V2.H4, V0.S4, V0.S4
	VUADDW2 V2.H8, V5.S4, V5.S4
	VUADDW V3.H4, V0.S4, V0.S4
	VUADDW2 V3.H8, V5.S4, V5.S4
	VUADDW V4.H4, V0.S4, V0.S4
	VUADDW2 V4.H8, V5.S4, V5.S4
	SUB $64, R1
	CBNZ R1, loop
	VADD V0.S4, V5.S4, V0.S4
	VADDV V0.S4, V0
	VMOV V0.S[0], R0
	MOVD R0, ret+24(FP)
	RET
