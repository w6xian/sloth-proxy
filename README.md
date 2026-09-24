# sloth-proxy

在 [sloth](https://github.com/w6xian/sloth) 通道上跑其它应用层协议：把内网一侧的服务
暴露到外网，不新开端口、不定义新帧。

它是**单向依赖** sloth 的独立仓库——sloth 不知道本仓库存在，两边各自发版。

```bash
go get github.com/w6xian/sloth-proxy
```

## 30 秒上手

场景：内网有一堆文件（或任何 `http.Handler`），想让外网通过 sloth 的现有连接访问。

**服务端**（能主动 `Call` 客户端的一侧）放网关：

```go
import (
    proxy "github.com/w6xian/sloth-proxy"
    proxyhttp "github.com/w6xian/sloth-proxy/http"
)

server := sloth.DefaultServer()
smap := sloth.NewSMap()          // 服务名 -> userId，由客户端 Reg 登记

gw := proxyhttp.NewGateway(server, smap, proxyhttp.WithLogger(proxy.SlothLogger()))

mux := http.NewServeMux()
mux.Handle("/m/{svc}/{path...}", proxyhttp.Auth(gw, checkToken))
http.ListenAndServe(":8080", mux)   // 起服务是使用方的事，库只给 Handler
```

**客户端**（内网一侧）把本地目录暴露出去：

```go
fwd := proxyhttp.Forward(http.FileServer(http.Dir(root)))
conn.Register(proxyhttp.Service, fwd, "")   // 注册成 "http" 服务的 Do 方法
```

完事。Range / 206 / Content-Type / MIME / 304 全部由 `http.FileServer` 提供，
两端都不用自己实现——`Forward` 直接调 `Handler`，**连本地端口都不占**。

### 上传：同一条通道，反向走

网关对 `POST / PUT` 走**整包转发**，body 原样带到客户端的 Handler：

```go
// 客户端：本地 Handler 里加一个收分片的路由
mux.HandleFunc("/_upload", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(io.LimitReader(r.Body, chunkMax))
    f, _ := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o644)
    f.WriteAt(body, offset)   // offset=0 时带 O_TRUNC 覆盖旧文件
})
```

**单次上限 60000 字节**（请求报文走 RPC 入参，受 ag 编码单参数 ≤ 65535 限制），
超过直接回 413、不浪费一次 RPC。大文件由前端切片、多次调用——
`examples/media` 的 web UI 按 48KB 一片传，客户端按偏移写入同一个文件，
和下载的分块是同一个思路。

完整可跑的例子见 `examples/media`（`go run ./examples/media/server` +
`go run ./examples/media/client -root ./.media`，然后打开
<http://localhost:8080> 看 web UI，或
`curl -r 0-99 http://localhost:8080/m/media/sample.bin -D -`）。

## 三条约束：非主动，不执行

库代码（examples 除外）不调用就不产生任何副作用：

1. **没有 `init()`**，没有全局注册、没有默认实例；
2. **不启动 goroutine**——缓存挂在实例上并惰性过期，谁创建谁释放；
3. **不持有生命周期**——不创建监听器、不创建 `http.Server`，只返回 `http.Handler`。

另外：不读环境变量、不读配置文件，日志默认丢弃（`WithLogger` 注入才输出）。
这三条由 `guard_test.go` 用 AST 自动检查，破戒会在 CI 上挂掉。

后果是好的：想嵌进自己的 mux 就嵌，想关就关，单测里也不需要真实网络。

## 目录

| 包 | 状态 | 说明 |
| --- | --- | --- |
| `proxy` | 可用 | 公共契约：`Caller`、`Resolver`、`Logger`、`Middleware`，以及与 sloth 的编译期断言 |
| `proxy/http` | 可用 | 网关（`NewGateway`）+ 转发服务（`Forward`），请求-响应型 |
| `proxy/ssh` | 预留 | 双向长流，需要会话语义，等 sloth 支持流式响应后落地 |
| `examples/media` | 可用 | 端到端示例：把内网目录暴露成 `/m/media/...` |
| `examples/ops` | 可用 | 端到端示例：Web 受限终端——浏览器敲命令，agent 在被管机执行，命令级白名单 + 强制审计 |

SOCKS5 与 SSH 同属"会话型"，共享同一套 `Session` 契约草案（写在 `ssh/doc.go` 里），
流式能力一到位可以一起落地。

## 调参

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `WithChunk` | 256KB | 单块大小。分块是为了不让大响应整包进内存 |
| `WithCallTimeout` | 30s | 单块调用超时；浏览器断连会经 `r.Context()` 提前取消 |
| `WithMaxReqBytes` | 60000 | 请求头上限（入参走 ag 编码，单参数 ≤ 65535），超了回 431 |
| `WithMaxRespBytes` | 32MB | 客户端侧单响应上限，超了直接报错而不是读进内存 |
| `WithSizeTTL` | 30s | 文件大小缓存；传 0 关闭（每次多一个 RTT 探测） |
| `WithLogger` | 丢弃 | 传 `proxy.SlothLogger()` 接到 sloth 的全局 logger |

## 断线重连

内网客户端通常比服务端先起，也要能扛住服务端重启，所以示例的做法是：

- 连不上（服务器还没起来 / 正在维护）→ 后台按 500ms → 30s 指数退避重试；
- 连上之后被断掉 → 立刻重连；
- 每次连接就绪回调 `OnReady` → **在里面重新 Sign / Reg**。

最后一条是关键：重连是一条全新连接，服务端 bucket 里挂的还是旧 channel，
不重新注册的话网关调不过来——表现为"客户端看着在线，但一律 404"。
注意**不能**在 `OnReady` 里同步发 RPC：读写循环（pump）还没跑起来，会等不到回包，
应另起 goroutine（示例就是这么做的）。

TCP 客户端的自动重连是 sloth `nrpc/tcp` 的能力。若你的 sloth 版本还没有这段
（v4.1.1 及更早没有，TCP 版原本是"断即结束"），就只能在业务侧自己轮询重拨。

## 已知边界

- **下载**只转发无 body 的请求（GET / HEAD）：入参上限 65535 字节只够放请求头；
  响应走返回值，是 fn 帧裸 payload，上限 1GB——一个分片绰绰有余，所以分块取。
- **上传**单次上限 60000 字节（含请求头），大文件要前端切片。
  真要做到"一次调用传大文件"，得等 sloth 的流式能力。
- 文件大小用 `Range: bytes=0-0` 探测并短期缓存，文件被替换后最多有 TTL 的窗口返回旧值。
- 没有心跳（FN 帧没有 ping/pong action），对端掉电时本端要等 TCP 超时才重连。

## 本地联调

依赖是 `go.mod` 里那行正式的 `require github.com/w6xian/sloth/v4 v4.2.0`——
**默认没有 `replace`、没有 `go.work`**，clone 下来就能编。

只有要对着自己本地**未发布**的 sloth 改动开发时，才临时建 workspace：

```bash
go work init . ../sloth/v4   # 两个仓库平级放在 github.com/ 下
```

`go.work` 不要提交（已加进 `.gitignore`）。用完删掉：有 go.work 时 `go build`
走的是本地源码，跟 `require` 的版本不是一回事——留着会让"能编过"变成假象。
