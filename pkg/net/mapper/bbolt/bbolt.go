package bbolt

/*
import (
	"fmt"
	"log"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	bolt "go.etcd.io/bbolt"
)

func sbbolt(s *bolt.Bucket, domain string) (resp []byte, ok bool) {
	z := newDomainStr(domain)
	first, asterisk := true, false

	for {
		if !z.hasNext() || s == nil {
			return
		}

		if r := s.Bucket([]byte(z.str())); r != nil {
			if symbol := r.Get(bSymbolKey); symbol != nil {
				// log.Println(symbol[0])
				if symbol[0] == wildcard {
					resp, ok = r.Get(bMarkKey), true
				}

				if symbol[0] == last && z.last() {
					return r.Get(bMarkKey), true
				}
			}

			s, first, _ = r, false, z.next()
			continue
		}

		if !first {
			return
		}

		if !asterisk {
			s, asterisk = s.Bucket([]byte("*")), true
			// log.Println("asterisk")
		} else {
			z.next()
		}
	}
}

var bSymbolKey = []byte{0x01}
var bMarkKey = []byte{0x02}

func storeBBoltMark(b *bolt.Bucket, symbol uint8, mark []byte) error {
	if err := b.Put(bSymbolKey, []byte{symbol}); err != nil {
		return err
	}

	if err := b.Put(bMarkKey, mark); err != nil {
		return err
	}

	return nil
}

func insertBBolt(b *bolt.Bucket, domain string, mark []byte) error {
	var err error
	z := newDomainStr(domain)
	for z.hasNext() {
		if z.last() && domain[0] == '*' {
			// b, err = b.CreateBucketIfNotExists([]byte("*"))
			// if err != nil {
			// return err
			// }

			if err := storeBBoltMark(b, wildcard, mark); err != nil {
				return err
			}
			break
		}

		b, err = b.CreateBucketIfNotExists([]byte(z.str()))
		if err != nil {
			return fmt.Errorf("create bucket [%s](%s) failed: %w", domain, z.str(), err)
		}

		if z.last() {
			if err = storeBBoltMark(b, last, mark); err != nil {
				return err
			}
		}

		z.next()
	}

	return nil
}

type bboltDomain struct{ db *bolt.DB }

func (d *bboltDomain) Insert(domain string, mark []byte) {
	if len(domain) == 0 {
		return
	}

	err := d.db.Update(func(tx *bolt.Tx) (err error) {
		var b *bolt.Bucket
		if domain[0] == '*' {
			b, err = tx.CreateBucketIfNotExists([]byte{'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 'r', 'o', 'o', 't'})
		} else {
			b, err = tx.CreateBucketIfNotExists([]byte{'r', 'o', 'o', 't'})
		}
		if err != nil {
			return err
		}

		if err := insertBBolt(b, domain, mark); err != nil {
			return fmt.Errorf("insert bbolt failed: %w", err)
		}

		return nil
	})
	if err != nil {
		log.Printf("insert %s failed: %w", domain, err)
	}
}

func (d *bboltDomain) Search(domain proxy.Address) (mark []byte, ok bool) {
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte{'r', 'o', 'o', 't'})
		if b != nil {
			mark, ok = sbbolt(b, domain.Hostname())
			if ok {
				return nil
			}
		}

		b = tx.Bucket([]byte{'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 'r', 'o', 'o', 't'})
		if b != nil {
			mark, ok = sbbolt(b, domain.Hostname())
		}

		return nil
	})
	if err != nil {
		log.Println(err)
	}

	return
}

func (d *bboltDomain) Clear() error {
	return d.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte{'r', 'o', 'o', 't'}); err != nil {
			return err
		}
		return tx.DeleteBucket([]byte{'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', 'r', 'o', 'o', 't'})
	})
}

func NewBBoltDomainMapper(db *bolt.DB) *bboltDomain {
	return &bboltDomain{db}
}
*/
