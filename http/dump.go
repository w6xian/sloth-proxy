package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// hopHeaders hop-by-hop 头：只对单条连接有效，不能跨跳转发
// （转发了会破坏两端的连接语义，例如 Transfer-Encoding: chunked）。
var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive",
	"Transfer-Encoding", "Upgrade", "Te", "Trailer",
}

// dumpRequest 把收到的请求序列化成 HTTP 报文，路径改写为客户端本地路径。
//
// 不能直接 r.Write()：它是服务端请求（RequestURI 是外部路径、Host 是网关地址），
// 转发过去客户端会拿着错误的目标去请求。
//
// rangeHeader 由网关统一下发（见 Gateway 的分块循环）；传空串表示不带 Range。
func dumpRequest(r *http.Request, host, path, rangeHeader string) ([]byte, error) {
	u := *r.URL
	u.Scheme = "http"
	u.Host = host // 占位：客户端会改写成自己的本地地址
	u.Path = path
	u.RawPath = ""

	req := &http.Request{
		Method:        r.Method,
		URL:           &u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        r.Header.Clone(),
		Host:          host,
		ContentLength: 0,
	}
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	// Range 由网关按 chunk 重算过，浏览器原来那段不能透传（可能跨整个文件）。
	// If-Range 也剥掉：客户端判定不匹配时会退回 200 整包，大文件就撞上限了。
	req.Header.Del("If-Range")
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	} else {
		req.Header.Del("Range")
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dumpRequestFull 序列化一个**带 body** 的请求（上传用）。
//
// 与 dumpRequest 的区别：它把 body 一起写进报文、不带 Range（上传不涉及分片取块），
// 且 ContentLength 按 body 实际长度填——客户端侧据此还原成一个普通的 POST/PUT。
func dumpRequestFull(r *http.Request, host, path string, body []byte) ([]byte, error) {
	u := *r.URL
	u.Scheme = "http"
	u.Host = host
	u.Path = path
	u.RawPath = ""

	req := &http.Request{
		Method:        r.Method,
		URL:           &u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        r.Header.Clone(),
		Host:          host,
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	for _, h := range hopHeaders {
		req.Header.Del(h)
	}
	// 上传不走分块：Range/If-Range 对它没有意义，带着反而让客户端判定
	req.Header.Del("Range")
	req.Header.Del("If-Range")
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readResponse 把对端回传的裸字节还原成响应报文。
func readResponse(raw []byte, req *http.Request) (*http.Response, error) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}
	return resp, nil
}

// writeResponse 解析客户端回传的响应报文并原样写给浏览器。
// 状态码、响应头、body 都来自客户端，网关不做任何改写。
func writeResponse(w http.ResponseWriter, r *http.Request, raw []byte) error {
	resp, err := readResponse(raw, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		// body 写了一半浏览器就断开是常态（播放器 seek），只记不报
		return fmt.Errorf("copy body: %w", err)
	}
	return nil
}

// copyHeader 复制上游响应头，跳过 hop-by-hop 头与我们要重写的长度相关头。
func copyHeader(dst, src http.Header) {
	for _, h := range hopHeaders {
		src.Del(h)
	}
	for k, vv := range src {
		// Content-Length / Content-Range 按"整个响应"重写，不能用单块的
		if k == "Content-Length" || k == "Content-Range" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
