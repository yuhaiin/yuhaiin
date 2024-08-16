package singleflight

import (
	"context"
	"testing"
	"time"
)

func TestSync(t *testing.T) {
	var g GroupSync[int, int]

	do := func() {
		_, err, _ := g.Do(context.TODO(), 1, func(context.Context) (int, error) {
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
