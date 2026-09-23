package http

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/w6xian/sloth-proxy"
)

// Gateway 服务端（外网）侧的入口：把一次 HTTP 请求翻译成对内网客户端的
// **若干次** RPC 调用。
//
// 它就是一个 http.Handler，不监听端口、不起 goroutine、不持有任何全局状态
// （文件大小缓存挂在实例上）。起服务、设超时、优雅退出都是调用方的事：
//
//	gw := proxyhttp.NewGateway(server, smap)
//	mux.Handle("/m/{svc}/{path...}", proxyhttp.Auth(gw, check))
//	http.ListenAndServe(":8080", mux)   // 这一步是用户的
//
// 只转发**无 body 的请求**（GET / HEAD）：入参上限 65535 字节只够放请求头，
// 带大 body 的请求要另想办法（扩 ag 长度字段或改走流式）。
type Gateway struct {
	caller   proxy.Caller
	resolver proxy.Resolver
	opt      *options

	// sizeCache 路径 → 文件大小的短缓存（见 WithSizeTTL）。
	// 挂在实例上而不是包级变量：Gateway 被丢弃时缓存随之释放，
	// 且不起清理 goroutine——只在读取时判断过期（惰性过期）。
	sizeCache sync.Map
}

// NewGateway 建一个网关。
//
// caller 通常是 *sloth.ClientRpc（ServerConn 用的那个），
// resolver 通常是 *sloth.SMap（服务名 → userId 的登记表）。
// 两者都只用到接口方法，测试时可以换成假实现。
func NewGateway(caller proxy.Caller, resolver proxy.Resolver, opts ...Option) *Gateway {
	return &Gateway{
		caller:   caller,
		resolver: resolver,
		opt:      newOptions(opts...),
	}
}

// ServeHTTP 实现 http.Handler。
//
// 服务名与路径取自 Go 1.22+ 的路由通配（mux.Handle("/m/{svc}/{path...}", gw)）。
// 用别的路由框架、或想自己决定这两段怎么取，直接调 Proxy 传进来。
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	svc := r.PathValue("svc")
	if svc == "" {
		http.Error(w, "missing service", http.StatusBadRequest)
		return
	}
	g.Proxy(w, r, svc, r.PathValue("path"))
}

// Proxy 转发一次请求：svc 是服务名，path 是客户端本地的路径。
func (g *Gateway) Proxy(w http.ResponseWriter, r *http.Request, svc, path string) {
	ctx := r.Context()

	// 未登记一律 404：不区分"不存在"与"未登记"，避免被拿来探测内网。
	userId, ok := g.resolver.Get(svc)
	if !ok {
		g.infow(ctx, "service not registered", "svc", svc)
		http.NotFound(w, r)
		return
	}

	// 上传（POST / PUT / DELETE 等）走**整包转发**：body 要原样带给客户端，
	// 不能进 Range 分块那条流程——那是"取字节"的逻辑，对写操作不成立。
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		g.passthrough(w, r, userId, svc, path)
		return
	}

	// 总大小：算 Range 边界、回答 416、填 Content-Range 都要它。
	size, ok := g.statSize(ctx, userId, svc, path)
	if !ok {
		g.errorw(ctx, "stat size failed", "svc", svc, "path", path)
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	startOff, endOff, err := rangeSpec(r.Header.Get("Range"), size)
	if errors.Is(err, errUnsatisfiable) {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	// 浏览器要了 Range 就回 206；没要也照样分块取，只是以 200 全量应答。
	ranged := !errors.Is(err, errNoRange)
	total := endOff - startOff + 1

	var (
		wroteHeader bool
		written     int64
		begin       = time.Now()
	)
	for off := startOff; off <= endOff; off += g.opt.chunk {
		last := min(off+g.opt.chunk-1, endOff)

		raw, err := dumpRequest(r, g.opt.host, "/"+path, fmt.Sprintf("bytes=%d-%d", off, last))
		if err != nil {
			g.errorw(ctx, "dump request failed", "err", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(raw) > g.opt.maxReqBytes {
			// 431：请求头过大，转发过去也会撞 ag 的参数上限
			http.Error(w, "request header too large", http.StatusRequestHeaderFieldsTooLarge)
			return
		}

		// 每块一次调用、一次超时：块只有 chunk 大小，默认 30s 足够；
		// 用 r.Context() 作父上下文，浏览器一断连在途调用立刻取消。
		callCtx, stop := context.WithTimeout(ctx, g.opt.callTimeout)
		resp, err := g.caller.Call(callCtx, userId, proxy.MethodHTTPDo, raw)
		stop()
		if err != nil {
			code := http.StatusBadGateway
			if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
			}
			g.errorw(ctx, "rpc forward failed", "svc", svc, "path", path,
				"offset", off, "userId", userId, "err", err)
			if !wroteHeader {
				http.Error(w, "upstream error", code)
			}
			return
		}

		up, err := readResponse(resp, r)
		if err != nil {
			g.errorw(ctx, "read upstream response failed", "svc", svc, "path", path, "err", err)
			if !wroteHeader {
				http.Error(w, "upstream error", http.StatusBadGateway)
			}
			return
		}

		// 我们总是带 Range 转发，期望 206。拿到别的（200 整包 / 404 / 304 /
		// 客户端自己判的 416）说明这是一次就能结束的响应，原样回写即可，
		// 不要往分块流程里掺。
		if up.StatusCode != http.StatusPartialContent {
			up.Body.Close()
			if err := writeResponse(w, r, resp); err != nil {
				g.errorw(ctx, "write response failed", "svc", svc, "path", path, "err", err)
			}
			return
		}

		if !wroteHeader {
			copyHeader(w.Header(), up.Header)
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
			if ranged {
				w.Header().Set("Content-Range",
					fmt.Sprintf("bytes %d-%d/%d", startOff, endOff, size))
				w.WriteHeader(http.StatusPartialContent)
			} else {
				w.WriteHeader(http.StatusOK)
			}
			wroteHeader = true
		}

		n, err := io.Copy(w, up.Body)
		up.Body.Close()
		written += n
		if err != nil {
			// 写一半浏览器就断开是常态（播放器 seek / 用户关页面），只记不报
			g.infow(ctx, "copy body stopped", "svc", svc, "path", path,
				"offset", off, "written", written, "err", err)
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if ctx.Err() != nil {
			g.infow(ctx, "client gone", "svc", svc, "path", path, "written", written)
			return
		}
	}
	g.infow(ctx, "forwarded", "svc", svc, "path", path, "size", size,
		"range", fmt.Sprintf("bytes=%d-%d", startOff, endOff),
		"written", written, "cost", time.Since(begin).String())
}

// passthrough 整包转发：一次请求 = 一次 RPC，body 原样带过去。
//
// 用于上传（POST / PUT）这类不带 Range 语义的写操作。
//
// 尺寸上限在这里卡死：请求报文走**入参**，受 ag 编码单参数 ≤ 65535 字节限制，
// 所以单次的"头 + body"不能超过 maxReqBytes（默认 60000）。要传更大的文件，
// 由前端切片、多次调用——这是协议层的约束，不是实现偷懒。
func (g *Gateway) passthrough(w http.ResponseWriter, r *http.Request, userId int64, svc, path string) {
	ctx := r.Context()

	// 先按上限读：读多了直接回 413，不让大 body 进内存、也不浪费一次 RPC
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(g.opt.maxReqBytes)+1))
	if err != nil {
		g.errorw(ctx, "read request body failed", "svc", svc, "path", path, "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > g.opt.maxReqBytes {
		// 413：报文超了入参上限，转发过去也会撞 ag 的参数上限
		g.infow(ctx, "request body too large", "svc", svc, "path", path,
			"bytes", len(body), "limit", g.opt.maxReqBytes)
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	raw, err := dumpRequestFull(r, g.opt.host, "/"+path, body)
	if err != nil {
		g.errorw(ctx, "dump request failed", "svc", svc, "path", path, "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(raw) > g.opt.maxReqBytes {
		http.Error(w, "request header too large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}

	callCtx, stop := context.WithTimeout(ctx, g.opt.callTimeout)
	resp, err := g.caller.Call(callCtx, userId, proxy.MethodHTTPDo, raw)
	stop()
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		g.errorw(ctx, "rpc forward failed", "svc", svc, "path", path,
			"method", r.Method, "userId", userId, "err", err)
		http.Error(w, "upstream error", code)
		return
	}
	if err := writeResponse(w, r, resp); err != nil {
		g.errorw(ctx, "write response failed", "svc", svc, "path", path, "err", err)
	}
}

// statSize 取文件大小：先查短缓存，没有就发一次 Range: bytes=0-0 探测。
//
// 探测只要响应头（1 字节 body），代价是一个 RTT，结果按 sizeTTL 缓存。
// 客户端是 http.FileServer，一定支持 Range；拿不到大小就当作上游异常。
//
// 缓存惰性过期：只在读取时判断 TTL，没有后台清理 goroutine。
func (g *Gateway) statSize(ctx context.Context, userId int64, svc, path string) (int64, bool) {
	key := svc + "\x00" + path
	if g.opt.sizeTTL > 0 {
		if v, ok := g.sizeCache.Load(key); ok {
			e, _ := v.(sizeEntry)
			if time.Since(e.at) < g.opt.sizeTTL {
				return e.size, true
			}
		}
	}
	probe := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: "/" + path},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       g.opt.host,
		Header:     http.Header{},
	}
	raw, err := dumpRequest(probe, g.opt.host, "/"+path, "bytes=0-0")
	if err != nil {
		g.errorw(ctx, "dump probe request failed", "svc", svc, "path", path, "err", err)
		return 0, false
	}
	callCtx, stop := context.WithTimeout(ctx, g.opt.callTimeout)
	defer stop()
	resp, err := g.caller.Call(callCtx, userId, proxy.MethodHTTPDo, raw)
	if err != nil {
		g.errorw(ctx, "probe failed", "svc", svc, "path", path, "err", err)
		return 0, false
	}
	up, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(resp)), probe)
	if err != nil {
		g.errorw(ctx, "read probe response failed", "svc", svc, "path", path, "err", err)
		return 0, false
	}
	defer up.Body.Close()

	size := up.ContentLength
	if cr := up.Header.Get("Content-Range"); cr != "" {
		// bytes 0-0/104857600 —— 斜杠后面才是总大小，Content-Length 是这一片的长度
		if i := strings.LastIndexByte(cr, '/'); i >= 0 {
			if n, err := strconv.ParseInt(cr[i+1:], 10, 64); err == nil {
				size = n
			}
		}
	}
	if size <= 0 {
		g.errorw(ctx, "unknown size", "svc", svc, "path", path,
			"status", up.StatusCode, "contentLength", up.ContentLength)
		return 0, false
	}
	if g.opt.sizeTTL > 0 {
		g.sizeCache.Store(key, sizeEntry{size: size, at: time.Now()})
	}
	return size, true
}

func (g *Gateway) infow(ctx context.Context, msg string, kvs ...any) {
	g.opt.logger.Infow(ctx, msg, kvs...)
}

func (g *Gateway) errorw(ctx context.Context, msg string, kvs ...any) {
	g.opt.logger.Errorw(ctx, msg, kvs...)
}

// sizeEntry 文件大小缓存项。
type sizeEntry struct {
	size int64
	at   time.Time
}
