package vmess

import (
	"crypto/md5"
	"encoding/binary"

	"github.com/google/uuid"
)

// User of vmess client
type User struct {
	UUID   uuid.UUID
	CmdKey [16]byte
}

// NewUser .
func NewUser(uuid uuid.UUID) *User {
	u := &User{UUID: uuid}
	copy(u.CmdKey[:], GetKey(uuid))
	return u
}

func nextID(oldID uuid.UUID) (newID uuid.UUID) {
	md5hash := md5.New()
	md5hash.Write(oldID[:])
	md5hash.Write([]byte("16167dc8-16b6-4e6d-b8bb-65dd68113a81"))
	var buf [16]byte
	for {
		md5hash.Sum(buf[:0])
		if newId, err := uuid.FromBytes(buf[:]); err == nil && newId != oldID {
			return newId
		}
		md5hash.Write([]byte("533eff8a-4113-4b10-b5ce-0f5d76b98cd2"))
	}
}

// GenAlterIDUsers generates users according to primary user's id and alterID
func (u *User) GenAlterIDUsers(alterID int) []*User {
	users := make([]*User, alterID)
	preID := u.UUID
	for i := 0; i < alterID; i++ {
		newID := nextID(preID)
		// NOTE: alterID user is a user which have a different uuid but a same cmdkey with the primary user.
		users[i] = &User{UUID: newID, CmdKey: u.CmdKey}
		preID = newID
	}

	return users
}

// GetKey returns the key of AES-128-CFB encrypter
// Key：MD5(UUID + []byte('c48619fe-8f02-49e0-b9e9-edf763e17e21'))
func GetKey(uuid uuid.UUID) []byte {
	md5hash := md5.New()
	md5hash.Write(uuid[:])
	md5hash.Write([]byte("c48619fe-8f02-49e0-b9e9-edf763e17e21"))
	return md5hash.Sum(nil)
}

// TimestampHash returns the iv of AES-128-CFB encrypter
// IV：MD5(X + X + X + X)，X = []byte(timestamp.now) (8 bytes, Big Endian)
func TimestampHash(t int64) []byte {
	md5hash := md5.New()

	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(t))
	md5hash.Write(ts)
	md5hash.Write(ts)
	md5hash.Write(ts)
	md5hash.Write(ts)
	return md5hash.Sum(nil)
}
