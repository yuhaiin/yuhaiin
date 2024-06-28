package singleflight

import (
	"testing"
	"time"
)

func TestSync(t *testing.T) {
	var g GroupSync[int, int]

	do := func() {
		_, err, _ := g.Do(1, func() (int, error) {
			time.Sleep(time.Second)
			t.Log("real do")
			return 1, nil
		})
		if err != nil {
			t.Error(err)
		}
	}
	for range 1000 {
		go do()
	}

	do()

	time.Sleep(time.Second * 2)
}
