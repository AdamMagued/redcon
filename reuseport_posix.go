//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package redcon

import "syscall"

func reusePortControl(network, address string, c syscall.RawConn) error {
	var operr error
	err := c.Control(func(fd uintptr) {
		operr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return operr
}
