//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package redcon

import "syscall"

func reusePortControl(network, address string, c syscall.RawConn) error {
	return ErrReusePortNotSupported
}
