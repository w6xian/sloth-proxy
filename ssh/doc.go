// Package ssh 是预留位：SSH over sloth 的落点，目前**没有任何可用代码**。
//
// # 为什么现在不实现
//
// HTTP 是"一问一答"：一次 RPC 拿一段，大不了借 Range 切成多次一问一答，
// 语义上完全够用。SSH 不是——它是**双向长流**：
//
//	握手（版本串 / KEX）→ 认证 → 会话 → 多路 channel（shell / exec / 端口转发）
//
// 一次连接要活几分钟到几小时，任意时刻两端都可能发数据，而且流量是字节流
// 不是报文。sloth 现在的语义是"一次 Call 一个回包"，要承载它只能把流切成
// 一段段乒乓往返（客户端 Call 上传、服务端 Call 下发），每帧一次 RPC 往返，
// 延迟和开销都难看，且流控、背压、乱序都要应用层自己扛。
//
// 所以正确顺序是：等 sloth 有**流式响应**（一次 Call 之后服务端可以连续推
// 多帧，或客户端/服务端任一侧建立可双向写的流），再在这里落地。届时分块
// 转发那套代码可以自动升级：探测到 Caller 实现了流式接口就走流，否则退回
// 现有的一问一答——调用方一行都不用改。
//
// # 草案（未落地，接口随时可能变）
//
//	// Session 一条双向字节流，对应 SSH 的一个 channel。
//	type Session interface {
//	    io.ReadWriteCloser
//	    // Resize 终端尺寸变化（pty 场景），非 pty 可返回 ErrUnsupported。
//	    Resize(cols, rows uint32) error
//	    // Exit 对端的退出码；流未结束前阻塞或返回 (0, ErrRunning)。
//	    Exit() (int, error)
//	}
//
//	// Dialer 在 sloth 通道上开一条到目标的会话，对应 SSH 的 DirectTCPIP。
//	type Dialer interface {
//	    Dial(ctx context.Context, svc string, addr string) (Session, error)
//	}
//
//	// Listener 反过来：内网一侧 Accept 外部发起的会话，对应端口转发与 sshd。
//	type Listener interface {
//	    Accept(ctx context.Context) (Session, error)
//	}
//
// 有了这三个东西，ssh 包要做的就只是：
//
//	ssh.NewClient(dialer)  → 起 golang.org/x/crypto/ssh 的连接，走端口转发
//	ssh.NewServer(listener) → 内网 sshd 侧的接受端
//
// SOCKS5 走的是同一套 Session 语义（握手之后就是双向转发），
// 所以流式能力一到位，socks5 与 ssh 可以一起落地，共享 proxy.Session 契约。
//
// 在那之前，本目录保持为空实现，避免把半成品接口固化成公开 API。
package ssh
