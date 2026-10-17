package gateway

import (
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux 上用 UDP GRO/GSO 转发后端回包：后端（sing-box 的 QUIC 实现）成批发出的数据报
// 在接收时由内核合并成一个缓冲（UDP_GRO），转发时整块交给内核按原大小切分（UDP_SEGMENT）。
// 一次系统调用处理几十个数据报，而不是每个数据报一次读、一次写。

// gsoDisabled 在内核或网卡不支持 GSO 时置位，此后逐个发送
var gsoDisabled atomic.Bool

// enableGRO 在后端 socket 上开启 UDP_GRO；失败（内核不支持）时照常逐个接收
func enableGRO(c *net.UDPConn) {
	if raw, err := c.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
		})
	}
}

// readBatch 读取一个（可能由 GRO 合并的）缓冲，返回长度和每个数据报的大小（0 表示未合并）
func readBatch(c *net.UDPConn, buf, oob []byte) (n, segment int, err error) {
	n, oobn, _, _, err := c.ReadMsgUDP(buf, oob)
	if err != nil {
		return 0, 0, err
	}
	msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
	if perr == nil {
		for _, m := range msgs {
			if m.Header.Level == unix.IPPROTO_UDP && m.Header.Type == unix.UDP_GRO && len(m.Data) >= 4 {
				segment = int(binary.NativeEndian.Uint32(m.Data))
			}
		}
	}
	return n, segment, nil
}

// writeBatch 把 buf 按 segment 大小发给 addr；可能时用一次 GSO 发送
func writeBatch(c *net.UDPConn, buf []byte, segment int, addr *net.UDPAddr) error {
	if segment <= 0 || segment >= len(buf) {
		_, err := c.WriteToUDP(buf, addr)
		return err
	}
	if !gsoDisabled.Load() {
		oob := make([]byte, unix.CmsgSpace(2))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		h.Level, h.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
		h.SetLen(unix.CmsgLen(2))
		binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(segment))
		_, _, err := c.WriteMsgUDP(buf, oob, addr)
		if err == nil {
			return nil
		}
		// EIO：网卡不支持校验和卸载；EINVAL/ENOPROTOOPT：内核不支持 UDP_SEGMENT
		if !errors.Is(err, syscall.EIO) && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOPROTOOPT) {
			return err
		}
		gsoDisabled.Store(true)
	}
	for off := 0; off < len(buf); off += segment {
		end := min(off+segment, len(buf))
		if _, err := c.WriteToUDP(buf[off:end], addr); err != nil {
			return err
		}
	}
	return nil
}
