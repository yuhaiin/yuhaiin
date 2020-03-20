package subscription

import (
	"log"
	"testing"
)

func TestGetNode(t *testing.T) {
	ssr := "ssr://MjIyLjIyMi4yMjIuMjIyOjQ0MzphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpodHRwX3Bvc3Q6ZEdWemRBby8/b2Jmc3BhcmFtPWRHVnpkQW8mcHJvdG9wYXJhbT1kR1Z6ZEFvJnJlbWFya3M9ZEdWemRBbyZncm91cD1kR1Z6ZEFvCg"
	s, _ := SsrParse(ssr)
	t.Log(s)
}

func TestSsrParse2(t *testing.T) {
	ssr := []string{"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz02YUtkNW9HcDZMcXImZ3JvdXA9NmFLZDVvR3A2THFy",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jMlZqYjI1ayZncm91cD02YUtkNW9HcDZMcXIK",
		"ssr://MS4xLjEuMTo1MzphdXRoX2NoYWluX2E6bm9uZTpodHRwX3NpbXBsZTo2YUtkNW9HcDZMcXIvP29iZnNwYXJhbT02YUtkNW9HcDZMcXImcHJvdG9wYXJhbT02YUtkNW9HcDZMcXImcmVtYXJrcz1jM056YzNOeiZncm91cD1jM056YzNOego",
		"ssr://MjIyLjIyMi4yMjIuMjIyOjQ0MzphdXRoX2FlczEyOF9tZDU6Y2hhY2hhMjAtaWV0ZjpodHRwX3Bvc3Q6ZEdWemRBby8/b2Jmc3BhcmFtPWRHVnpkQW8mcHJvdG9wYXJhbT1kR1Z6ZEFvJnJlbWFya3M9ZEdWemRBbyZncm91cD1kR1Z6ZEFvCg"}

	for x := range ssr {
		log.Println(SsrParse2(ssr[x]))
	}
}
