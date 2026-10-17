package gateway

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// 浏览器真实发出的 QUIC Initial 数据报（testdata/browser/*.bin，每个文件一个连接），
// 由抓包提取：依次为 2 字节长度 + 数据报内容。覆盖 Chrome 打散 CRYPTO 帧等实际情况
func TestBrowserInitials(t *testing.T) {
	files, _ := filepath.Glob("testdata/browser/*.bin")
	if len(files) == 0 {
		t.Skip("no browser captures")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var datagrams [][]byte
			for len(data) >= 2 {
				n := int(binary.BigEndian.Uint16(data))
				datagrams, data = append(datagrams, data[2:2+n]), data[2+n:]
			}
			hello, used := assemble(t, datagrams)
			if hello == nil || hello.ServerName == "" {
				t.Fatalf("ClientHello with SNI not assembled from %d datagrams", len(datagrams))
			}
			t.Logf("sni=%s alpn=%v datagrams=%d", hello.ServerName, hello.SupportedProtos, used)
		})
	}
}
