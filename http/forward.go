package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// Forwarder 客户端（内网）侧的转发服务。
//
// 它只有一个导出方法 Do，签名正是 sloth 反射注册要求的形态：
//
//	conn.Register(proxyhttp.Service, proxyhttp.Forward(h), "")
//
// 服务端网关调 "http.Do" 时就会走到 Do。不起监听器、不起 goroutine——
// 传进来的 http.Handler 是被**直接调用**的，不占端口。
type Forwarder struct {
	rt  http.RoundTripper
	opt *options
}

// Forward 把本地的 http.Handler 暴露成转发服务。
//
// 请求不经过网络：内部用一个直接调 Handler 的 RoundTripper，
// 所以 http.FileServer 的 Range / MIME / 304 全部照常工作，且不占端口。
func Forward(h http.Handler, opts ...Option) *Forwarder {
	o := newOptions(opts...)
	return &Forwarder{rt: &handlerTransport{handler: h, host: o.host}, opt: o}
}

// ForwardTo 把请求打给一个真实的 RoundTripper。
//
// 用于"客户端要代理的不是本地 handler，而是内网另一台机器上的 http 服务"
// 的场景；rt 一般传 http.DefaultTransport 或自定义的 Transport。
// 注意这时它是真的会往外发请求的——但依然只在 Do 被调用时发生。
func ForwardTo(rt http.RoundTripper, opts ...Option) *Forwarder {
	o := newOptions(opts...)
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Forwarder{rt: rt, opt: o}
}

// Do 收到一个完整的 HTTP 请求报文，返回一个完整的 HTTP 响应报文。
//
// 方法名与签名都是契约的一部分，不要改。
func (f *Forwarder) Do(ctx context.Context, raw []byte) ([]byte, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return nil, fmt.Errorf("bad request: %w", err)
	}
	// RoundTrip 要求 RequestURI 为空（那是服务端请求才有的字段）
	req.RequestURI = ""
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		req.URL.Host = f.opt.host
	}

	resp, err := f.rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("round trip: %w", err)
	}
	defer resp.Body.Close()

	// 先按上限读，超了直接放弃：不让大响应整包进内存
	var body bytes.Buffer
	n, err := io.Copy(&body, io.LimitReader(resp.Body, f.opt.maxRespBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if n > f.opt.maxRespBytes {
		return nil, fmt.Errorf("response too large: %d bytes (limit %d)", n, f.opt.maxRespBytes)
	}

	resp.Body = io.NopCloser(&body)
	resp.ContentLength = int64(body.Len())

	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		return nil, fmt.Errorf("write response: %w", err)
	}
	f.opt.logger.Infow(ctx, "proxied", "method", req.Method, "path", req.URL.Path,
		"status", resp.StatusCode, "bytes", buf.Len())
	return buf.Bytes(), nil
}

// handlerTransport 直接调 http.Handler 的 RoundTripper：不监听、不拨号。
type handlerTransport struct {
	handler http.Handler
	host    string
}

func (t *handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "" {
		req.URL.Host = t.host
	}
	rec := &responseRecorder{header: http.Header{}, code: http.StatusOK}
	t.handler.ServeHTTP(rec, req)
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", rec.code, http.StatusText(rec.code)),
		StatusCode:    rec.code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rec.header,
		Body:          io.NopCloser(&rec.body),
		ContentLength: int64(rec.body.Len()),
		Request:       req,
	}, nil
}

// responseRecorder 最小 http.ResponseWriter，只留 Handler 用得到的部分
// （不用 httptest.NewRecorder：那属于测试包，不该出现在库代码里）。
type responseRecorder struct {
	code   int
	header http.Header
	body   bytes.Buffer
	wrote  bool
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.code = code
	r.wrote = true
}
