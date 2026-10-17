package lightweight

// PacketViewReader optionally avoids copying an adapter's input buffer into a
// second scratch buffer. The view is borrowed until the next read or Close.
// checksumVerified is a trust boundary: it may only describe a transport checksum
// validated by the adapter/kernel, or locally generated checksum-partial data
// from an offload-aware TUN. IP/transport structure is still checked by the core.
// Ordinary remote wire packets must retain checksum validation.
type PacketViewReader interface {
	ReadPacketView() (packet []byte, checksumVerified bool, err error)
}

// PacketBufferWriter optionally accepts owned packet storage with reserved
// prefix bytes. It borrows the buffer until return. segmentSize=0 is an ordinary
// complete packet; a positive value requests TCP GSO with that wire payload MSS.
// MaxGSOPacketSize must be zero unless that request is supported. Headroom and
// capabilities are fixed for the lifetime of the link. Close interrupts writes.
type PacketBufferWriter interface {
	Headroom() int
	MaxGSOPacketSize() int
	WritePacketBuffer(buffer []byte, offset, segmentSize int) error
}

const maxPacketHeadroom = 64
const maxPacketBufferSize = 65575 + maxPacketHeadroom
