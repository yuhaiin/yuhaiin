package api

import "sync/atomic"

func (c *Counter) AddUpload(n uint64)   { atomic.AddUint64(&c.xxx_hidden_Upload, n) }
func (c *Counter) AddDownload(n uint64) { atomic.AddUint64(&c.xxx_hidden_Download, n) }
func (c *Counter) LoadUpload() uint64   { return atomic.LoadUint64(&c.xxx_hidden_Upload) }
func (c *Counter) LoadDownload() uint64 { return atomic.LoadUint64(&c.xxx_hidden_Download) }
