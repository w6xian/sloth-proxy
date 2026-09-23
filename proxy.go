package proxy

import (
	"context"
	"net/http"

	"github.com/w6xian/sloth/v4"
)

// 服务名与方法名的约定。两端必须一致，否则调过去是空方法。
const (
	// ServiceHTTP 客户端侧注册的 RPC 服务名。
	ServiceHTTP = "http"
	// MethodDo 转发方法名（签名固定为 Do(ctx, raw []byte) ([]byte, error)）。
	MethodDo = "Do"
	// MethodHTTPDo 服务端网关实际调用的方法全名。
	MethodHTTPDo = ServiceHTTP + "." + MethodDo
)

// Caller 把一次调用打到某个 userId 的能力——*sloth.ClientRpc 就是这个东西。
//
// 参数与 sloth 的 Call 完全一致：userId 是目标连接（服务提供者拿到的是负数
//
//	userId，与 Sign 分给普通客户端的正数 ID 不冲突），mtd 是方法全名，
//	arg 传裸字节。返回的是对端方法的返回值，本仓库的转发服务返回的是
//	完整的 HTTP 响应报文。
type Caller interface {
	Call(ctx context.Context, userId int64, mtd string, arg ...any) ([]byte, error)
}

// Resolver 服务名 → userId 的登记表——*sloth.SMap 就是这个东西。
//
// 查不到一律按"不存在"处理，不区分"没登记"和"已下线"，避免被拿来探测内网。
type Resolver interface {
	Get(name string) (int64, bool)
}

// 编译期断言：sloth 的两个类型天然满足上面的契约，不用写任何适配器。
// 这也是本仓库 import sloth 的唯一理由——一旦 sloth 改了签名，这里立刻报错。
var (
	_ Caller   = (*sloth.ClientRpc)(nil)
	_ Resolver = (*sloth.SMap)(nil)
)

// Logger 日志门面。签名与 sloth.Infow / sloth.Errorw 一致，
// 因此 SlothLogger() 可以直接把日志接到 sloth 的全局 logger 上。
//
// 默认实现是 NopLogger：什么都不写。想看日志就显式注入——这与
// "非主动，不执行"是同一条原则，库不能自己往 stdout 上吐东西。
type Logger interface {
	Infow(ctx context.Context, msg string, kvs ...any)
	Errorw(ctx context.Context, msg string, kvs ...any)
}

// NopLogger 丢弃所有日志（默认）。
type NopLogger struct{}

func (NopLogger) Infow(context.Context, string, ...any)  {}
func (NopLogger) Errorw(context.Context, string, ...any) {}

// SlothLogger 返回转发给 sloth 全局 logger 的实现。
//
// 用法：proxyhttp.NewGateway(caller, resolver, proxyhttp.WithLogger(proxy.SlothLogger()))。
// 注意它跟随 sloth 的日志级别（sloth.SetLogLevel 控制），本身不起任何后台。
func SlothLogger() Logger { return slothLogger{} }

type slothLogger struct{}

func (slothLogger) Infow(ctx context.Context, msg string, kvs ...any) {
	sloth.Infow(ctx, msg, kvs...)
}

func (slothLogger) Errorw(ctx context.Context, msg string, kvs ...any) {
	sloth.Errorw(ctx, msg, kvs...)
}

// Middleware 包在网关外面的 http.Handler 装饰器。
//
// 鉴权、限流这类横切逻辑放这里，不进转发主流程——网关只负责搬运，
// 不该知道"谁可以访问"。
type Middleware func(http.Handler) http.Handler

// Chain 按顺序套一串中间件：Chain(a, b, c)(h) 等价于 a(b(c(h)))。
func Chain(ms ...Middleware) Middleware {
	return func(h http.Handler) http.Handler {
		for i := len(ms) - 1; i >= 0; i-- {
			if ms[i] != nil {
				h = ms[i](h)
			}
		}
		return h
	}
}
