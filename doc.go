// Package proxy 是跑在 sloth 之上的**应用层隧道**工具集。
//
// # 它不属于 sloth 协议
//
// sloth 只负责"把一次调用送到某个 userId、拿回一段字节"。
// 至于这段字节是 HTTP 报文、SOCKS5 握手还是 SSH 会话，协议层不关心，
// 本仓库也不定义任何新的帧——每个子包都是把一种既有协议**塞进**这条
// 已有通道里搬运。所以它与 sloth 是单向依赖（本仓库 import sloth，
// sloth 不知道本仓库存在），可以各自发版。
//
// # 三条硬约束：非主动，不执行
//
// 本仓库的**库代码**（examples 除外）必须做到"不调用就不产生任何副作用"：
//
//  1. 没有 init()，不做任何全局注册（没有隐藏的 registry、没有默认实例）；
//  2. 不启动 goroutine——不起后台清理、不起探测、不起预热；
//     缓存一律惰性过期，在读取时判断，谁创建谁持有（挂在实例上，不是包级变量）；
//  3. 不持有生命周期——不创建监听器、不创建 http.Server，只返回
//     http.Handler；端口、超时、优雅退出全是调用方的事。
//
// 另外：不读环境变量、不读配置文件、日志默认丢弃（用 WithLogger 注入才输出）。
// 这三条由 guard_test.go 自动检查，破戒会在 CI 上挂掉。
//
// # 怎么用
//
// 服务端（能主动 Call 客户端的一侧）放网关，客户端（内网一侧）放转发服务：
//
//	// 服务端：把 /m/{svc}/{path...} 打到内网客户端
//	gw := proxyhttp.NewGateway(server, smap)          // *sloth.ClientRpc / *sloth.SMap
//	mux.Handle("/m/{svc}/{path...}", proxyhttp.Auth(gw, check))
//
//	// 客户端：把本地目录（或任何 http.Handler）暴露成 "http" 服务
//	conn.Register(proxyhttp.Service, proxyhttp.Forward(http.FileServer(http.Dir(root))), "")
//
// 两端都不需要新协议、新端口、新帧。
//
// # 子包现状
//
//	proxy/http   可用：请求-响应型，一次 RPC 一段，借 Range 分块
//	proxy/ssh    预留：双向长流，需要会话语义，等 sloth 支持流式响应后落地
package proxy
