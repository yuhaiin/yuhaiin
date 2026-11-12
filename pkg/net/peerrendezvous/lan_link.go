package peerrendezvous

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/netip"
	"sync"
)

const (
	linkControlMagic = "YHL1"
	linkChunkSize    = 1000
	linkMaxChunks    = 8
	linkHeaderSize   = 16 + 32 + 2 + 2
)

type LinkOffer struct {
	PublicKey   [32]byte   `json:"publicKey"`
	PublisherIP netip.Addr `json:"publisherIp"`
	ClientIP    netip.Addr `json:"clientIp"`
	Routes      []string   `json:"routes"`
}

// LinkExchange authenticates provisioning independently of the rendezvous
// coordinator. Each response is bound to a fresh challenge from the outbound.
type LinkExchange struct {
	role      Role
	cipher    cipher.AEAD
	localKey  [32]byte
	offer     []byte
	offerHash [32]byte

	mu        sync.Mutex
	remoteKey [32]byte
	challenge [16]byte
	hash      [32]byte
	chunks    [linkMaxChunks][]byte
	result    chan LinkOffer
}

func NewLinkExchange(token [32]byte, role Role, localKey [32]byte, offer LinkOffer) (*LinkExchange, error) {
	block, err := aes.NewCipher(token[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	x := &LinkExchange{role: role, cipher: aead, localKey: localKey, result: make(chan LinkOffer, 1)}
	rand.Read(x.challenge[:])
	if role == Publisher {
		offer.PublicKey = localKey
		x.offer, err = json.Marshal(offer)
		if err != nil {
			return nil, err
		}
		if len(x.offer) > linkMaxChunks*linkChunkSize {
			return nil, errors.New("LAN Link assignment exceeds the control message limit")
		}
		x.offerHash = sha256.Sum256(x.offer)
	}
	return x, nil
}

func (x *LinkExchange) Results() <-chan LinkOffer { return x.result }

func (x *LinkExchange) request(s *Socket) {
	if x.role != Dialer || s.peer.Load() == nil {
		return
	}
	x.mu.Lock()
	request := append(x.challenge[:16:16], x.localKey[:]...)
	x.mu.Unlock()
	_, _ = s.WriteTo(x.seal(Dialer, request), nil)
}

func (x *LinkExchange) seal(role Role, payload []byte) []byte {
	header := append([]byte(linkControlMagic), byte(role))
	return x.cipher.Seal(header, nil, payload, header)
}

func (x *LinkExchange) receive(s *Socket, packet []byte, peer *net.UDPAddr) bool {
	if !bytes.HasPrefix(packet, []byte(linkControlMagic)) {
		return false
	}
	headerSize := len(linkControlMagic) + 1
	if len(packet) <= headerSize || Role(packet[headerSize-1]) != 1-x.role {
		return true
	}
	payload, err := x.cipher.Open(nil, nil, packet[headerSize:], packet[:headerSize])
	if err != nil {
		return true
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.role == Publisher {
		x.respond(s, peer, payload)
	} else {
		x.accept(payload)
	}
	return true
}

func (x *LinkExchange) respond(s *Socket, peer *net.UDPAddr, request []byte) {
	if len(request) != 48 {
		return
	}
	key := [32]byte(request[16:])
	if key == [32]byte{} || key == x.localKey || (x.remoteKey != [32]byte{} && x.remoteKey != key) {
		return
	}
	if x.remoteKey == [32]byte{} {
		x.remoteKey = key
		x.publish(LinkOffer{PublicKey: key})
	}
	total := (len(x.offer) + linkChunkSize - 1) / linkChunkSize
	for i := range total {
		payload := append(make([]byte, 0, linkHeaderSize+linkChunkSize), request[:16]...)
		payload = append(payload, x.offerHash[:]...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(i))
		payload = binary.BigEndian.AppendUint16(payload, uint16(total))
		payload = append(payload, x.offer[i*linkChunkSize:min((i+1)*linkChunkSize, len(x.offer))]...)
		_, _ = s.PacketConn.WriteTo(x.seal(Publisher, payload), peer)
	}
}

func (x *LinkExchange) accept(payload []byte) {
	if len(payload) <= linkHeaderSize || len(payload) > linkHeaderSize+linkChunkSize || !bytes.Equal(payload[:16], x.challenge[:]) {
		return
	}
	hash := [32]byte(payload[16:48])
	index, total := int(binary.BigEndian.Uint16(payload[48:50])), int(binary.BigEndian.Uint16(payload[50:52]))
	if total == 0 || total > linkMaxChunks || index >= total {
		return
	}
	if hash != x.hash {
		clear(x.chunks[:])
		x.hash = hash
	}
	x.chunks[index] = payload[linkHeaderSize:]
	var data []byte
	for _, chunk := range x.chunks[:total] {
		if chunk == nil {
			return
		}
		data = append(data, chunk...)
	}
	var offer LinkOffer
	if sha256.Sum256(data) != hash || json.Unmarshal(data, &offer) != nil || offer.PublicKey == [32]byte{} ||
		offer.PublicKey == x.localKey || (x.remoteKey != [32]byte{} && x.remoteKey != offer.PublicKey) {
		return
	}
	x.remoteKey = offer.PublicKey
	rand.Read(x.challenge[:])
	clear(x.chunks[:])
	x.publish(offer)
}

func (x *LinkExchange) publish(offer LinkOffer) {
	select {
	case <-x.result:
	default:
	}
	x.result <- offer
}
