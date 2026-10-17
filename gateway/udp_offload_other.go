//go:build !linux

package gateway

import "net"

func enableGRO(*net.UDPConn) {}

func readBatch(c *net.UDPConn, buf, _ []byte) (n, segment int, err error) {
	n, err = c.Read(buf)
	return n, 0, err
}

func writeBatch(c *net.UDPConn, buf []byte, _ int, addr *net.UDPAddr) error {
	_, err := c.WriteToUDP(buf, addr)
	return err
}
