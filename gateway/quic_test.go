package gateway

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestInitialKeysRFC9001(t *testing.T) {
	// RFC 9001 附录 A.1：DCID 0x8394c8f03e515708 推导出的客户端 Initial 密钥
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	keys, err := deriveInitialKeys(quicV1, dcid)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(keys.iv); got != "fa044b2f42a3fd3b46fb255c" {
		t.Fatalf("iv = %s", got)
	}
	// hp 密钥无法从 cipher.Block 取回，用 RFC 附录 A.2 的 sample 验证掩码
	sample, _ := hex.DecodeString("d1b1c98dd7689fb8ec11d242b123dc9b")
	mask := make([]byte, 16)
	keys.hp.Encrypt(mask, sample)
	if got := hex.EncodeToString(mask[:5]); got != "437b9aec36" {
		t.Fatalf("header protection mask = %s", got)
	}
}

// captureInitials 用 quic-go 客户端向一个只收不回的 UDP 端口发起连接，返回收到的数据报
func captureInitials(t *testing.T, version quic.Version, sni string) [][]byte {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go quic.DialAddr(ctx, pc.LocalAddr().String(),
		&tls.Config{ServerName: sni, NextProtos: []string{"h3"}},
		&quic.Config{Versions: []quic.Version{version}})

	var datagrams [][]byte
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		datagrams = append(datagrams, slices.Clone(buf[:n]))
	}
	if len(datagrams) == 0 {
		t.Fatal("no datagrams captured")
	}
	return datagrams
}

// assemble 依次喂入数据报，返回解析出的 ClientHello 和用到的数据报数
func assemble(t *testing.T, datagrams [][]byte) (*tls.ClientHelloInfo, int) {
	t.Helper()
	var a cryptoAssembler
	for i, d := range datagrams {
		if !isQUICInitial(d) {
			t.Fatalf("datagram %d is not a QUIC Initial", i)
		}
		payloads, err := decryptInitials(d)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		for _, p := range payloads {
			if err := a.add(p); err != nil {
				t.Fatalf("datagram %d: %v", i, err)
			}
		}
		if msg := a.clientHello(); msg != nil {
			return parseClientHelloMessage(msg), i + 1
		}
	}
	return nil, len(datagrams)
}

func TestQUICClientHello(t *testing.T) {
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(v.String(), func(t *testing.T) {
			datagrams := captureInitials(t, v, "hy2.example.com")
			hello, used := assemble(t, datagrams)
			if hello == nil {
				t.Fatalf("ClientHello not assembled from %d datagrams", len(datagrams))
			}
			if hello.ServerName != "hy2.example.com" || !slices.Contains(hello.SupportedProtos, "h3") {
				t.Fatalf("unexpected hello: sni=%q alpn=%v", hello.ServerName, hello.SupportedProtos)
			}
			t.Logf("ClientHello assembled from %d datagram(s)", used)
		})
	}
}

func TestQUICClientHelloOutOfOrder(t *testing.T) {
	datagrams := captureInitials(t, quic.Version1, "hy2.example.com")
	// 首次发送的 ClientHello 可能跨多个数据报；取到组装完成为止的那几个，倒序喂入
	_, used := assemble(t, datagrams)
	if used < 2 {
		t.Skip("ClientHello fits in one datagram; nothing to reorder")
	}
	first := slices.Clone(datagrams[:used])
	slices.Reverse(first)
	hello, _ := assemble(t, first)
	if hello == nil || hello.ServerName != "hy2.example.com" {
		t.Fatalf("out-of-order datagrams should still assemble, got %+v", hello)
	}
}

func TestNotQUIC(t *testing.T) {
	if isQUICInitial([]byte("GET / HTTP/1.1\r\n")) {
		t.Fatal("plain text is not a QUIC Initial")
	}
	if _, err := decryptInitials([]byte{0x40, 1, 2, 3, 4, 5, 6, 7}); err == nil {
		t.Fatal("short header datagram should not decrypt as Initial")
	}
}
