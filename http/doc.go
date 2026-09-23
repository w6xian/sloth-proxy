// Package http 在 sloth 通道上跑 HTTP：把内网一侧的 HTTP 服务暴露到外网。
//
// # 它不做的事
//
// 不定义新帧、不实现 Range / MIME / 304 / Content-Type——这些全部由客户端
// 本地的 http.FileServer（或你自己的 http.Handler）提供。本包只负责搬运：
//
//	浏览器 ──HTTP──▶ Gateway（服务端侧）
//	                  ① 请求报文序列化（req.Write）
//	                  ② caller.Call(ctx, userId, "http.Do", raw)
//	                                  ──────▶ Forwarder（客户端侧）还原请求、打给本地 Handler
//	                                  ◀────── 响应报文（裸字节）
//	                  ③ 解析响应报文、回写给浏览器
//	浏览器 ◀──HTTP── Gateway
//
// 一次 RPC 承载一个完整的 HTTP 报文，于是 Range / 206 / MIME 一行都不用写。
//
// # 尺寸上的两个前提
//
//   - 请求走**入参**：受 ag 编码限制单参数 ≤ 65535 字节；
//   - 响应走**返回值**：是 fn 帧裸 payload，上限 1GB → 一个分片绰绰有余。
//
// 于是网关有两条路径：
//
//	下载 GET/HEAD  → 分块：按 chunk 一段段要字节，响应的每一片都很小
//	上传 POST/PUT  → 整包：一次请求一次 RPC，body 原样带过去（见 passthrough）
//
// 上传的**单次**上限就是请求报文上限（默认 60000 字节，含请求头），
// 所以大文件要由前端切片、多次调用——这是协议层的约束，不是实现偷懒。
// 真要做到"一次调用传大文件"，得等 sloth 的流式能力。
//
// # 两侧各一个对象
//
//	服务端：gw := NewGateway(server, smap)   // *sloth.ClientRpc + *sloth.SMap
//	        mux.Handle("/m/{svc}/{path...}", gw)
//
//	客户端：conn.Register(Service, Forward(http.FileServer(http.Dir(root))), "")
//
// 都不起 goroutine、不起监听器（Forward 直接调 Handler，不占端口），
// 生命周期全在使用方手里——见根包 proxy 的"非主动，不执行"。
//
// # 导入建议
//
// 包名与标准库同为 http，使用侧请起别名：
//
//	import proxyhttp "github.com/w6xian/sloth-proxy/http"
package http

// Method 两端约定的 RPC 方法全名，见 proxy.MethodHTTPDo。
const Method = "http.Do"

// Service 客户端侧注册时的 RPC 服务名，见 proxy.ServiceHTTP。
const Service = "http"
