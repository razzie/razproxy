package razproxy

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/razzie/babble"
)

func getPrivateIPBlocks() (blocks []*net.IPNet) {
	// https://stackoverflow.com/a/50825191
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		blocks = append(blocks, block)
	}
	return
}

var privateIPBlocks = getPrivateIPBlocks()

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func uniqueID() string {
	i := uint16(time.Now().UnixNano())
	babbler := babble.NewBabbler()
	return fmt.Sprintf("%s-%x", babbler.Babble(), i)
}
