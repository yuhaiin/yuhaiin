package dns

import (
	"log"
	"testing"
)

func TestCache_Match(t *testing.T) {
	cache := NewDnsCache()
	cache.Add("google.com", []string{"1.0.0.1"})
	cache.Add("twitter.com", []string{"1.0.0.1"})
	cache.Add("github.com", []string{"1.0.0.1"})
	cache.Add("facebook.com", []string{"1.0.0.1"})
	log.Println(cache.Get("google.com"))
}
