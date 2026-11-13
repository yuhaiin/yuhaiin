package peerrendezvous

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	json "encoding/json/v2"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
)

const (
	linkControlMagic = "YHL1"
	// linkPeersMagic marks the peer list messages. Gateways and clients that
	// predate them pass the messages to WireGuard, which drops them.
	linkPeersMagic    = "YHP1"
	linkChunkSize     = 1000
	linkMaxChunks     = 8
	linkMaxPeerChunks = 128
	linkHeaderSize    = 16 + 16 + 2 + 2
)

type LinkOffer struct {
	PublicKey   [32]byte   `json:"publicKey"`
	PublisherIP netip.Addr `json:"publisherIp"`
	ClientIP    netip.Addr `json:"clientIp"`
	Routes      []string   `json:"routes"`
	// Subnet is the tunnel network, advertised when the gateway relays
	// client-to-client traffic. Empty means clients reach the shared routes
	// only.
	Subnet string `json:"subnet,omitempty"`
	// PublisherIPs, ClientIPs and Subnets hold every address family of a
	// dual-stack tunnel, IPv4 first. The single-value fields above repeat the
	// family of the first route for clients that predate them.
	PublisherIPs []netip.Addr `json:"publisherIps,omitempty"`
	ClientIPs    []netip.Addr `json:"clientIps,omitempty"`
	Subnets      []string     `json:"subnets,omitempty"`
}

// Tunnel returns the tunnel addresses and subnets of every family.
func (o LinkOffer) Tunnel() (publisher, client []netip.Addr, subnets []string) {
	if len(o.PublisherIPs) != 0 || len(o.ClientIPs) != 0 {
		return o.PublisherIPs, o.ClientIPs, o.Subnets
	}
	if o.Subnet != "" {
		subnets = []string{o.Subnet}
	}
	return []netip.Addr{o.PublisherIP}, []netip.Addr{o.ClientIP}, subnets
}

// SameAssignment reports whether two offers assign the same tunnel.
func (o LinkOffer) SameAssignment(next LinkOffer) bool {
	return o.PublisherIP == next.PublisherIP && o.ClientIP == next.ClientIP && o.Subnet == next.Subnet &&
		slices.Equal(o.Routes, next.Routes) && slices.Equal(o.PublisherIPs, next.PublisherIPs) &&
		slices.Equal(o.ClientIPs, next.ClientIPs) && slices.Equal(o.Subnets, next.Subnets)
}

// LinkExchange authenticates provisioning independently of the rendezvous
// coordinator. Each response is bound to a fresh challenge from the outbound.
type LinkExchange struct {
	role     Role
	cipher   cipher.AEAD
	localKey [32]byte
	offer    []byte
	offerID  [16]byte

	mu         sync.Mutex
	remoteKey  [32]byte
	challenge  [16]byte
	receivedID [16]byte
	chunkCount int
	chunks     [linkMaxChunks][]byte
	result     chan LinkOffer

	// The peer list travels separately from the offer: the gateway sends it
	// again only when the client reports an older version.
	peers          []byte
	peersID        [16]byte
	peersChallenge [16]byte
	peerChunks     map[uint16][]byte
	peerReceiving  [16]byte
	peerTotal      int
	onPeers        func([]byte)
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
	rand.Read(x.peersChallenge[:])
	if role == Publisher {
		offer.PublicKey = localKey
		x.offer, err = json.Marshal(offer)
		if err != nil {
			return nil, err
		}
		if len(x.offer) > linkMaxChunks*linkChunkSize {
			return nil, errors.New("LAN Link assignment exceeds the control message limit")
		}
		rand.Read(x.offerID[:])
	}
	return x, nil
}

func (x *LinkExchange) Results() <-chan LinkOffer { return x.result }

// SetPeers sets the peer list a publisher serves. A changed list gets a new
// random version; clients fetch it again only when the version changes.
func (x *LinkExchange) SetPeers(data []byte) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.peers != nil && bytes.Equal(x.peers, data) {
		return
	}
	x.peers = bytes.Clone(data)
	rand.Read(x.peersID[:])
}

// OnPeers sets the function that receives each new peer list on a dialer.
func (x *LinkExchange) OnPeers(f func([]byte)) {
	x.mu.Lock()
	x.onPeers = f
	x.mu.Unlock()
}

func (x *LinkExchange) request(s *Socket) {
	if x.role != Dialer || s.peer.Load() == nil {
		return
	}
	x.mu.Lock()
	request := append(x.challenge[:16:16], x.localKey[:]...)
	var peers []byte
	if x.remoteKey != [32]byte{} {
		peers = append(x.peersChallenge[:16:16], x.peersID[:]...)
	}
	x.mu.Unlock()
	_, _ = s.WriteTo(x.seal(linkControlMagic, Dialer, request), nil)
	if peers != nil {
		_, _ = s.WriteTo(x.seal(linkPeersMagic, Dialer, peers), nil)
	}
}

func (x *LinkExchange) seal(magic string, role Role, payload []byte) []byte {
	header := append([]byte(magic), byte(role))
	return x.cipher.Seal(header, nil, payload, header)
}

func (x *LinkExchange) receive(s *Socket, packet []byte, peer *net.UDPAddr) bool {
	peers := bytes.HasPrefix(packet, []byte(linkPeersMagic))
	if !peers && !bytes.HasPrefix(packet, []byte(linkControlMagic)) {
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
	switch {
	case peers && x.role == Publisher:
		x.respondPeers(s, peer, payload)
	case peers:
		if data := x.acceptPeers(payload); data != nil && x.onPeers != nil {
			f := x.onPeers
			x.mu.Unlock()
			f(data)
			return true
		}
	case x.role == Publisher:
		x.respond(s, peer, payload)
	default:
		x.accept(payload)
	}
	x.mu.Unlock()
	return true
}

// respondPeers sends the peer list when the client holds another version.
func (x *LinkExchange) respondPeers(s *Socket, peer *net.UDPAddr, request []byte) {
	if len(request) != 32 || x.peers == nil || [16]byte(request[16:]) == x.peersID {
		return
	}
	total := max(1, (len(x.peers)+linkChunkSize-1)/linkChunkSize)
	if total > linkMaxPeerChunks {
		return
	}
	for i := range total {
		payload := append(make([]byte, 0, linkHeaderSize+linkChunkSize), request[:16]...)
		payload = append(payload, x.peersID[:]...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(i))
		payload = binary.BigEndian.AppendUint16(payload, uint16(total))
		payload = append(payload, x.peers[i*linkChunkSize:min((i+1)*linkChunkSize, len(x.peers))]...)
		_, _ = s.PacketConn.WriteTo(x.seal(linkPeersMagic, Publisher, payload), peer)
	}
}

// acceptPeers collects peer list chunks and returns the list once complete.
func (x *LinkExchange) acceptPeers(payload []byte) []byte {
	if len(payload) < linkHeaderSize || len(payload) > linkHeaderSize+linkChunkSize || !bytes.Equal(payload[:16], x.peersChallenge[:]) {
		return nil
	}
	id := [16]byte(payload[16:32])
	index, total := binary.BigEndian.Uint16(payload[32:34]), int(binary.BigEndian.Uint16(payload[34:36]))
	if id == x.peersID || total == 0 || total > linkMaxPeerChunks || int(index) >= total {
		return nil
	}
	if x.peerChunks == nil || id != x.peerReceiving || total != x.peerTotal {
		x.peerChunks, x.peerReceiving, x.peerTotal = make(map[uint16][]byte, total), id, total
	}
	x.peerChunks[index] = bytes.Clone(payload[linkHeaderSize:])
	if len(x.peerChunks) < total {
		return nil
	}
	var data []byte
	for i := range uint16(total) {
		data = append(data, x.peerChunks[i]...)
	}
	x.peersID, x.peerChunks = id, nil
	rand.Read(x.peersChallenge[:])
	return data
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
		payload = append(payload, x.offerID[:]...)
		payload = binary.BigEndian.AppendUint16(payload, uint16(i))
		payload = binary.BigEndian.AppendUint16(payload, uint16(total))
		payload = append(payload, x.offer[i*linkChunkSize:min((i+1)*linkChunkSize, len(x.offer))]...)
		_, _ = s.PacketConn.WriteTo(x.seal(linkControlMagic, Publisher, payload), peer)
	}
}

func (x *LinkExchange) accept(payload []byte) {
	if len(payload) <= linkHeaderSize || len(payload) > linkHeaderSize+linkChunkSize || !bytes.Equal(payload[:16], x.challenge[:]) {
		return
	}
	id := [16]byte(payload[16:32])
	index, total := int(binary.BigEndian.Uint16(payload[32:34])), int(binary.BigEndian.Uint16(payload[34:36]))
	if total == 0 || total > linkMaxChunks || index >= total {
		return
	}
	// The authenticated offer ID keeps chunks from different assignments
	// apart if the gateway restarts while an exchange is in progress.
	if x.chunkCount == 0 || id != x.receivedID {
		clear(x.chunks[:])
		x.receivedID, x.chunkCount = id, total
	} else if total != x.chunkCount {
		return
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
	if json.Unmarshal(data, &offer) != nil || offer.PublicKey == [32]byte{} ||
		offer.PublicKey == x.localKey || (x.remoteKey != [32]byte{} && x.remoteKey != offer.PublicKey) {
		return
	}
	x.remoteKey = offer.PublicKey
	rand.Read(x.challenge[:])
	x.chunkCount = 0
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
