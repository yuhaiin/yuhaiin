package disk

import (
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/v2/internal/diskio"
)

type region = diskio.Region

func openRegion(path string) (*region, error) { return diskio.OpenRegion(path) }

func writeAll(writer io.Writer, data []byte) error { return diskio.WriteAll(writer, data) }
