package http

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/w6xian/sloth-proxy"
)

// testFileSize 测试文件大小；内容可预测（i%251），方便校验 Range 字节是否正确。
const testFileSize = 1 << 20

func writeTestFile(t *testing.T, dir string) {
	t.Helper()
	buf := make([]byte, testFileSize)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	if err := os.WriteFile(filepath.Join(dir, "sample.bin"), buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeResolver 假的登记表：只认 "media"。
type fakeResolver struct{ users map[string]int64 }

func (r fakeResolver) Get(name string) (int64, bool) {
	v, ok := r.users[name]
	return v, ok
}

// fakeCaller 假的 Caller：把网关发来的报文交给真实的 Forwarder（背后是
// http.FileServer）。于是不起网络就能端到端验证 Range / 206 / 分块拼接。
type fakeCaller struct {
	fwd    *Forwarder
	method string
	calls  int
}

func (c *fakeCaller) Call(ctx context.Context, userId int64, mtd string, arg ...any) ([]byte, error) {
	c.calls++
	if mtd != c.method {
		return nil, errors.New("unknown method: " + mtd)
	}
	if len(arg) == 0 {
		return nil, errors.New("no argument")
	}
	raw, ok := arg[0].([]byte)
	if !ok {
		return nil, errors.New("argument is not []byte")
	}
	return c.fwd.Do(ctx, raw)
}

func newTestGateway(t *testing.T, opts ...Option) (*Gateway, *fakeCaller) {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir)
	fwd := Forward(http.FileServer(http.Dir(dir)), opts...)
	caller := &fakeCaller{fwd: fwd, method: proxy.MethodHTTPDo}
	gw := NewGateway(caller, fakeResolver{users: map[string]int64{"media": -1}}, opts...)
	return gw, caller
}

func TestGatewayFullContent(t *testing.T) {
	gw, _ := newTestGateway(t)

	req := httptest.NewRequest(http.MethodGet, "/m/media/sample.bin", nil)
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "media", "sample.bin")

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if got := rec.Body.Len(); got != testFileSize {
		t.Fatalf("body len = %d, want %d", got, testFileSize)
	}
	for i, b := range rec.Body.Bytes() {
		if b != byte(i%251) {
			t.Fatalf("byte %d = %d, want %d", i, b, byte(i%251))
		}
	}
}

func TestGatewayRange(t *testing.T) {
	cases := []struct {
		name        string
		header      string
		wantCode    int
		wantRange   string
		wantLen     int
		wantFirst   byte
		wantContent string
	}{
		{"前 100 字节", "bytes=0-99", 206, "bytes 0-99/1048576", 100, 0, ""},
		{"后缀 100 字节", "bytes=-100", 206, "bytes 1048476-1048575/1048576", 100,
			byte((testFileSize - 100) % 251), ""},
		{"开区间", "bytes=1048476-", 206, "bytes 1048476-1048575/1048576", 100,
			byte((testFileSize - 100) % 251), ""},
		{"越界 416", "bytes=1048576-", 416, "bytes */1048576", 0, 0, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw, _ := newTestGateway(t)
			req := httptest.NewRequest(http.MethodGet, "/m/media/sample.bin", nil)
			req.Header.Set("Range", c.header)
			rec := httptest.NewRecorder()
			gw.Proxy(rec, req, "media", "sample.bin")

			if rec.Code != c.wantCode {
				t.Fatalf("code = %d, want %d", rec.Code, c.wantCode)
			}
			if got := rec.Header().Get("Content-Range"); got != c.wantRange {
				t.Fatalf("Content-Range = %q, want %q", got, c.wantRange)
			}
			if c.wantCode == 416 {
				return
			}
			body := rec.Body.Bytes()
			if len(body) != c.wantLen {
				t.Fatalf("body len = %d, want %d", len(body), c.wantLen)
			}
			if body[0] != c.wantFirst {
				t.Fatalf("first byte = %d, want %d", body[0], c.wantFirst)
			}
		})
	}
}

// TestGatewayChunked 小 chunk 走多块拼接：验证分块循环不是"只取一块"。
func TestGatewayChunked(t *testing.T) {
	const chunk = 4096
	const want = 40 * 1024 // 10 块
	gw, caller := newTestGateway(t, WithChunk(chunk))

	req := httptest.NewRequest(http.MethodGet, "/m/media/sample.bin", nil)
	req.Header.Set("Range", "bytes=0-40959")
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "media", "sample.bin")

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("code = %d, want 206", rec.Code)
	}
	if rec.Body.Len() != want {
		t.Fatalf("body len = %d, want %d", rec.Body.Len(), want)
	}
	for i, b := range rec.Body.Bytes() {
		if b != byte(i%251) {
			t.Fatalf("byte %d = %d, want %d", i, b, byte(i%251))
		}
	}
	// 10 块数据 + 1 次 size 探测
	if caller.calls != 11 {
		t.Fatalf("caller calls = %d, want 11", caller.calls)
	}
}

func TestGatewayUnknownService(t *testing.T) {
	gw, _ := newTestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/m/nope/sample.bin", nil)
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "nope", "sample.bin")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

// TestGatewayUpstreamError 上游报错要回 502，而不是把错误吞成 200。
func TestGatewayUpstreamError(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir)
	fwd := Forward(http.FileServer(http.Dir(dir)))
	caller := &fakeCaller{fwd: fwd, method: "wrong.method"}
	gw := NewGateway(caller, fakeResolver{users: map[string]int64{"media": -1}})

	req := httptest.NewRequest(http.MethodGet, "/m/media/sample.bin", nil)
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "media", "sample.bin")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
}

func TestForwarderRoundTrip(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir)
	fwd := Forward(http.FileServer(http.Dir(dir)))

	src := httptest.NewRequest(http.MethodGet, "/sample.bin", nil)
	src.Header.Set("Range", "bytes=10-19")
	raw, err := dumpRequest(src, DefaultHost, "/sample.bin", "bytes=10-19")
	if err != nil {
		t.Fatal(err)
	}
	out, err := fwd.Do(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(out)), src)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 10 {
		t.Fatalf("body len = %d, want 10", len(body))
	}
	if body[0] != byte(10%251) {
		t.Fatalf("first byte = %d, want %d", body[0], byte(10%251))
	}
}

// TestForwarderTooLarge 响应超上限要报错，不能整包读进内存。
func TestForwarderTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir)
	fwd := Forward(http.FileServer(http.Dir(dir)), WithMaxRespBytes(1024))

	src := httptest.NewRequest(http.MethodGet, "/sample.bin", nil)
	raw, err := dumpRequest(src, DefaultHost, "/sample.bin", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fwd.Do(context.Background(), raw); err == nil {
		t.Fatal("want error for oversized response")
	}
}

// TestGatewayUpload POST 走整包转发：body 必须原样出现在客户端那一侧。
func TestGatewayUpload(t *testing.T) {
	var (
		got    []byte
		method string
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		got = b
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("saved"))
	})
	caller := &fakeCaller{fwd: Forward(h), method: proxy.MethodHTTPDo}
	gw := NewGateway(caller, fakeResolver{users: map[string]int64{"media": -1}})

	body := bytes.Repeat([]byte("u"), 5000)
	req := httptest.NewRequest(http.MethodPost, "/m/media/up.bin", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "media", "up.bin")

	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d, want 201", rec.Code)
	}
	if method != http.MethodPost {
		t.Fatalf("upstream method = %s, want POST", method)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("upstream body len = %d, want %d", len(got), len(body))
	}
	if rec.Body.String() != "saved" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "saved")
	}
}

// TestGatewayUploadTooLarge 超过请求上限要回 413，且不该浪费一次 RPC。
func TestGatewayUploadTooLarge(t *testing.T) {
	caller := &fakeCaller{fwd: Forward(http.NotFoundHandler()), method: proxy.MethodHTTPDo}
	gw := NewGateway(caller, fakeResolver{users: map[string]int64{"media": -1}},
		WithMaxReqBytes(1000))

	req := httptest.NewRequest(http.MethodPost, "/m/media/up.bin",
		bytes.NewReader(bytes.Repeat([]byte("u"), 5000)))
	rec := httptest.NewRecorder()
	gw.Proxy(rec, req, "media", "up.bin")

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rec.Code)
	}
	if caller.calls != 0 {
		t.Fatalf("caller calls = %d, want 0 (不该打到客户端)", caller.calls)
	}
}

// TestNoGoroutineLeak 一轮转发之后不该留下 goroutine——库不起后台。
func TestNoGoroutineLeak(t *testing.T) {
	gw, _ := newTestGateway(t)
	before := runtime.NumGoroutine()

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/m/media/sample.bin", nil)
		req.Header.Set("Range", "bytes=0-8191")
		gw.Proxy(httptest.NewRecorder(), req, "media", "sample.bin")
	}
	runtime.Gosched()
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines: before=%d after=%d", before, after)
	}
}

// TestSizeCacheBounded 连查不同路径后缓存条目可控（惰性过期，无清理 goroutine）。
func TestSizeCacheBounded(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir)
	fwd := Forward(http.FileServer(http.Dir(dir)))
	caller := &fakeCaller{fwd: fwd, method: proxy.MethodHTTPDo}
	gw := NewGateway(caller, fakeResolver{users: map[string]int64{"media": -1}})

	ctx := context.Background()
	if _, ok := gw.statSize(ctx, -1, "media", "sample.bin"); !ok {
		t.Fatal("stat failed")
	}
	size, ok := gw.statSize(ctx, -1, "media", "sample.bin")
	if !ok || size != testFileSize {
		t.Fatalf("size = %d ok = %v, want %d", size, ok, testFileSize)
	}
	// 第二次不该再发 RPC（命中缓存）
	if caller.calls != 1 {
		t.Fatalf("caller calls = %d, want 1 (cached)", caller.calls)
	}
}
