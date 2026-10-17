package gateway

import (
	"testing"

	"github.com/quic-go/quic-go"
)

// 种子是 quic-go 生成的真实 Initial 数据报，变异后能深入到解密和帧解析
func addInitialSeeds(f *testing.F) [][]byte {
	var all [][]byte
	for _, v := range []quic.Version{quic.Version1, quic.Version2} {
		for _, d := range captureInitials(f, v, "hy2.example.com") {
			f.Add(d)
			all = append(all, d)
		}
	}
	return all
}

func FuzzDecryptInitials(f *testing.F) {
	addInitialSeeds(f)
	f.Add([]byte{})
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0xff})
	f.Fuzz(func(t *testing.T, datagram []byte) {
		_ = isQUICInitial(datagram)
		payloads, _ := decryptInitials(datagram)
		var a cryptoAssembler
		for _, p := range payloads {
			if a.add(p) != nil {
				break
			}
		}
	})
}

func FuzzCryptoAssembler(f *testing.F) {
	for _, d := range addInitialSeeds(f) {
		if payloads, err := decryptInitials(d); err == nil {
			for _, p := range payloads {
				f.Add(p)
			}
		}
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		var a cryptoAssembler
		_ = a.add(payload)
		_ = a.add(payload) // 重复的帧
		if a.total > maxClientHello {
			t.Fatalf("buffered %d bytes, limit %d", a.total, maxClientHello)
		}
		if msg := a.clientHello(); msg != nil {
			_ = parseClientHelloMessage(msg)
		}
	})
}
