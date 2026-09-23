package http

import (
	"time"

	"github.com/w6xian/sloth-proxy"
)

// 默认值。都是"调用方不配也能跑"的量，不是魔法数——改之前先看下面的注释。
const (
	// DefaultChunk 单次转发的数据块大小。
	//
	// 为什么必须分块：客户端那边的响应是**整包进内存**的（resp.Write 写进一个
	// bytes.Buffer 再返回），还有 DefaultMaxRespBytes 兜底。100MB 的 mp4 整包
	// 转发一定撞上限；就算放宽上限，内存峰值也是文件大小的好几倍。
	// 分块之后每块只有 256KB：永远不触发上限，网关与客户端内存恒定在几百 KB，
	// 与文件大小无关；浏览器的 Range 本来就是现成的分块协议，拖动/快进
	// 直接映射到某几块。
	DefaultChunk = 256 << 10

	// DefaultCallTimeout 单次转发调用的超时。
	// 块只有 256KB，30s 足够；浏览器断连会经 r.Context() 提前取消。
	DefaultCallTimeout = 30 * time.Second

	// DefaultMaxReqBytes 请求报文上限。入参走 ag 编码，单参数上限 65535
	// （ArgumentMaxDataSize），留一点余量给报文头本身。超了回 431。
	DefaultMaxReqBytes = 60000

	// DefaultMaxRespBytes 客户端侧单个响应的上限（不分块时的兜底）。
	DefaultMaxRespBytes = 32 << 20

	// DefaultSizeTTL 文件大小（Stat）的缓存时间。
	//
	// 每个 Range 请求都先探测一次 size 会多一个 RTT，播放器拖动时尤其明显。
	// 文件被替换后最多有 TTL 的窗口返回旧 size——点播场景可接受，
	// 真要强一致就把 ETag 一起缓存比对。
	DefaultSizeTTL = 30 * time.Second

	// DefaultHost 转发报文里的占位 Host。客户端侧会用自己本地的地址覆盖，
	// 只有在直连 http.Handler（Forward）时才真正用到。
	DefaultHost = "proxy.local"
)

// options 网关与转发服务共用一份配置，各自只取自己认得的字段。
type options struct {
	chunk        int64
	callTimeout  time.Duration
	maxReqBytes  int
	maxRespBytes int64
	sizeTTL      time.Duration
	logger       proxy.Logger
	host         string
}

// Option 配置回调。传给 NewGateway 或 Forward。
type Option func(*options)

func newOptions(opts ...Option) *options {
	o := &options{
		chunk:        DefaultChunk,
		callTimeout:  DefaultCallTimeout,
		maxReqBytes:  DefaultMaxReqBytes,
		maxRespBytes: DefaultMaxRespBytes,
		sizeTTL:      DefaultSizeTTL,
		logger:       proxy.NopLogger{},
		host:         DefaultHost,
	}
	for _, fn := range opts {
		if fn != nil {
			fn(o)
		}
	}
	return o
}

// WithChunk 单次转发的数据块大小（<=0 表示用默认值）。
func WithChunk(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.chunk = n
		}
	}
}

// WithCallTimeout 单次 RPC 调用的超时（<=0 表示用默认值）。
// 用请求的 ctx 作父上下文，浏览器一断连在途调用立刻取消。
func WithCallTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.callTimeout = d
		}
	}
}

// WithMaxReqBytes 请求报文上限，超过回 431（<=0 表示用默认值）。
func WithMaxReqBytes(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.maxReqBytes = n
		}
	}
}

// WithMaxRespBytes 客户端侧单个响应的上限（<=0 表示用默认值）。
// 超过会直接报错而不是把整包读进内存。
func WithMaxRespBytes(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxRespBytes = n
		}
	}
}

// WithSizeTTL 文件大小的缓存时间。传 0 表示关闭缓存（每次都探测，多一个 RTT）。
func WithSizeTTL(d time.Duration) Option {
	return func(o *options) {
		if d >= 0 {
			o.sizeTTL = d
		}
	}
}

// WithLogger 注入日志。默认丢弃全部日志（proxy.NopLogger）。
// 想接到 sloth 的全局 logger 就传 proxy.SlothLogger()。
func WithLogger(l proxy.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// WithHost 转发报文里的占位 Host（默认 DefaultHost）。
func WithHost(h string) Option {
	return func(o *options) {
		if h != "" {
			o.host = h
		}
	}
}
