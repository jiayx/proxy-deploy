package gateway

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"
)

// QUIC Initial 包解析（RFC 9000 / 9001，以及 RFC 9369 的 QUIC v2）。
//
// 客户端的 Initial 包虽然加密，但密钥只由明文的 Destination Connection ID 推导，
// 任何中间节点都能解密。解密后从 CRYPTO 帧重组出 TLS ClientHello，取得 SNI 用于路由。
// ClientHello 可能跨多个包，CRYPTO 帧也可能乱序、分散（Chrome 会刻意打散），所以按偏移量重组。

const (
	quicV1 = 0x00000001
	quicV2 = 0x6b3343cf
)

var (
	saltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	saltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

	errNotInitial = errors.New("not a QUIC Initial packet")
)

// initialKeys 是客户端 Initial 包的解密材料
type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

func deriveInitialKeys(version uint32, dcid []byte) (*initialKeys, error) {
	salt, prefix := saltV1, "quic "
	if version == quicV2 {
		salt, prefix = saltV2, "quicv2 "
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, err
	}
	client := expandLabel(initial, "client in", sha256.Size)
	key := expandLabel(client, prefix+"key", 16)
	iv := expandLabel(client, prefix+"iv", 12)
	hpKey := expandLabel(client, prefix+"hp", 16)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	return &initialKeys{aead: aead, iv: iv, hp: hp}, nil
}

// expandLabel 是 TLS 1.3 的 HKDF-Expand-Label（RFC 8446 7.1），context 为空
func expandLabel(secret []byte, label string, length int) []byte {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err) // 只会在长度超限时发生，这里的长度都是常量
	}
	return out
}

// isQUICInitial 粗略判断数据报是否以客户端 Initial 包开头（不解密）
func isQUICInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	typ := (b[0] >> 4) & 0x03
	return (version == quicV1 && typ == 0) || (version == quicV2 && typ == 1)
}

// decryptInitials 解密数据报中所有的客户端 Initial 包（一个数据报可能合并多个 QUIC 包），
// 返回解密后的载荷。数据报里的其他包类型（如 0-RTT）被跳过。
func decryptInitials(datagram []byte) ([][]byte, error) {
	var payloads [][]byte
	for len(datagram) > 0 {
		if datagram[0]&0x80 == 0 {
			break // 短包头只会出现在握手完成后，也只能在数据报末尾
		}
		pkt, rest, err := splitLongHeaderPacket(datagram)
		if err != nil {
			return payloads, err
		}
		datagram = rest
		if !isQUICInitial(pkt) {
			continue
		}
		payload, err := decryptInitial(pkt)
		if err != nil {
			return payloads, err
		}
		payloads = append(payloads, payload)
	}
	if len(payloads) == 0 {
		return nil, errNotInitial
	}
	return payloads, nil
}

// longHeader 是长包头中解析出的字段；pnOffset 是包号（受保护）的起始位置
type longHeader struct {
	version  uint32
	dcid     []byte
	pnOffset int
	length   int // 包号 + 载荷的长度
}

func parseLongHeader(b []byte) (*longHeader, error) {
	r := quicReader{b: b, off: 5}
	if len(b) < 5 {
		return nil, errNotInitial
	}
	h := &longHeader{version: binary.BigEndian.Uint32(b[1:5])}
	dcidLen, ok := r.byte()
	if !ok || dcidLen > 20 {
		return nil, fmt.Errorf("invalid destination connection id")
	}
	if h.dcid, ok = r.bytes(int(dcidLen)); !ok {
		return nil, errNotInitial
	}
	scidLen, ok := r.byte()
	if !ok || scidLen > 20 {
		return nil, fmt.Errorf("invalid source connection id")
	}
	if _, ok = r.bytes(int(scidLen)); !ok {
		return nil, errNotInitial
	}
	if isQUICInitial(b) {
		tokenLen, ok := r.varint()
		if !ok {
			return nil, errNotInitial
		}
		if _, ok = r.bytes(int(tokenLen)); !ok {
			return nil, errNotInitial
		}
	}
	length, ok := r.varint()
	if !ok || r.off+int(length) > len(b) {
		return nil, fmt.Errorf("truncated QUIC packet")
	}
	h.pnOffset, h.length = r.off, int(length)
	return h, nil
}

// splitLongHeaderPacket 从数据报开头切出一个长包头 QUIC 包
func splitLongHeaderPacket(b []byte) (pkt, rest []byte, err error) {
	h, err := parseLongHeader(b)
	if err != nil {
		return nil, nil, err
	}
	end := h.pnOffset + h.length
	return b[:end], b[end:], nil
}

// decryptInitial 去除包头保护并解密一个客户端 Initial 包，返回帧数据
func decryptInitial(pkt []byte) ([]byte, error) {
	h, err := parseLongHeader(pkt)
	if err != nil {
		return nil, err
	}
	keys, err := deriveInitialKeys(h.version, h.dcid)
	if err != nil {
		return nil, err
	}
	if h.pnOffset+4+16 > len(pkt) {
		return nil, fmt.Errorf("QUIC packet too short for header protection sample")
	}
	pkt = bytes.Clone(pkt)
	mask := make([]byte, 16)
	keys.hp.Encrypt(mask, pkt[h.pnOffset+4:h.pnOffset+4+16])
	pkt[0] ^= mask[0] & 0x0f
	pnLen := int(pkt[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		pkt[h.pnOffset+i] ^= mask[1+i]
	}

	nonce := bytes.Clone(keys.iv)
	for i := 0; i < pnLen; i++ {
		nonce[len(nonce)-pnLen+i] ^= pkt[h.pnOffset+i]
	}
	header := pkt[:h.pnOffset+pnLen]
	ciphertext := pkt[h.pnOffset+pnLen : h.pnOffset+h.length]
	return keys.aead.Open(nil, nonce, ciphertext, header)
}

// cryptoAssembler 按偏移量重组客户端 Initial 包中 CRYPTO 帧的数据
type cryptoAssembler struct {
	chunks map[uint64][]byte
	total  int
}

// maxClientHello 限制重组缓冲，避免恶意数据占用内存
const maxClientHello = 64 * 1024

// add 解析一个 Initial 包载荷中的帧，收集 CRYPTO 数据
func (a *cryptoAssembler) add(payload []byte) error {
	if a.chunks == nil {
		a.chunks = map[uint64][]byte{}
	}
	r := quicReader{b: payload}
	for r.off < len(payload) {
		typ, _ := r.varint()
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK：largest acknowledged、ack delay、range count、first range，
			// 再加 range count 组 (gap, length)，ACK_ECN 另有 3 个计数
			_, ok1 := r.varint()
			_, ok2 := r.varint()
			count, ok3 := r.varint()
			_, ok4 := r.varint()
			if !ok1 || !ok2 || !ok3 || !ok4 || count > maxClientHello {
				return errBadFrame
			}
			fields := count * 2
			if typ == 0x03 {
				fields += 3
			}
			for i := uint64(0); i < fields; i++ {
				if _, ok := r.varint(); !ok {
					return errBadFrame
				}
			}
		case 0x06: // CRYPTO
			offset, ok1 := r.varint()
			length, ok2 := r.varint()
			data, ok3 := r.bytes(int(length))
			if !ok1 || !ok2 || !ok3 {
				return errBadFrame
			}
			if offset+length > maxClientHello {
				return fmt.Errorf("ClientHello exceeds %d bytes", maxClientHello)
			}
			if old, dup := a.chunks[offset]; !dup || len(data) > len(old) {
				a.total += len(data) - len(old)
				a.chunks[offset] = bytes.Clone(data)
			}
		case 0x1c: // CONNECTION_CLOSE
			return fmt.Errorf("client closed the connection")
		default:
			return fmt.Errorf("unexpected frame type 0x%x in Initial packet", typ)
		}
	}
	return nil
}

var errBadFrame = errors.New("malformed QUIC frame")

// contiguous 返回从偏移 0 开始连续的 CRYPTO 数据
func (a *cryptoAssembler) contiguous() []byte {
	offsets := make([]uint64, 0, len(a.chunks))
	for off := range a.chunks {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	var out []byte
	for _, off := range offsets {
		chunk := a.chunks[off]
		end := off + uint64(len(chunk))
		switch {
		case off > uint64(len(out)):
			return out // 中间有缺口
		case end > uint64(len(out)):
			out = append(out, chunk[uint64(len(out))-off:]...)
		}
	}
	return out
}

// clientHello 在 ClientHello 消息完整后返回它，否则返回 nil
func (a *cryptoAssembler) clientHello() []byte {
	data := a.contiguous()
	if len(data) < 4 {
		return nil
	}
	if data[0] != 0x01 { // handshake type client_hello
		return nil
	}
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+n {
		return nil
	}
	return data[:4+n]
}

// parseClientHelloMessage 解析一条完整的 ClientHello 握手消息。
// 把它包装成 TLS 记录交给 peekClientHello，复用 crypto/tls 的解析。
func parseClientHelloMessage(msg []byte) *tls.ClientHelloInfo {
	var records []byte
	for len(msg) > 0 {
		n := min(len(msg), 16384)
		records = append(records, 0x16, 0x03, 0x01, byte(n>>8), byte(n))
		records = append(records, msg[:n]...)
		msg = msg[n:]
	}
	hello, _ := peekClientHello(&bytesConn{r: bytes.NewReader(records)})
	return hello
}

// bytesConn 是只读的内存连接，供 crypto/tls 解析使用
type bytesConn struct{ r *bytes.Reader }

func (c *bytesConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *bytesConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *bytesConn) Close() error                     { return nil }
func (c *bytesConn) LocalAddr() net.Addr              { return nil }
func (c *bytesConn) RemoteAddr() net.Addr             { return nil }
func (c *bytesConn) SetDeadline(time.Time) error      { return nil }
func (c *bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bytesConn) SetWriteDeadline(time.Time) error { return nil }

// quicReader 按 QUIC 编码读取字节和变长整数
type quicReader struct {
	b   []byte
	off int
}

func (r *quicReader) byte() (byte, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	r.off++
	return r.b[r.off-1], true
}

func (r *quicReader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	r.off += n
	return r.b[r.off-n : r.off], true
}

// varint 读取 QUIC 变长整数（RFC 9000 16）
func (r *quicReader) varint() (uint64, bool) {
	first, ok := r.byte()
	if !ok {
		return 0, false
	}
	n := 1 << (first >> 6)
	v := uint64(first & 0x3f)
	rest, ok := r.bytes(n - 1)
	if !ok {
		return 0, false
	}
	for _, b := range rest {
		v = v<<8 | uint64(b)
	}
	return v, true
}
