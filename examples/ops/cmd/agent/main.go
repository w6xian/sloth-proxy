package main

// sloth-proxy 的 agent：跑在被管机器上。
//
// 它只做两件事：
//  1. 注册 "ops" 服务（Exec / Output），把本机变成一个可受控执行端；
//  2. 连上 gate 并把自己登记成服务提供者（v1.Sign + v1.Reg），
//     之后 gate 用 server.Call(userId, "ops.Exec", ...) 把命令打过来。
//
// 注意它**不监听任何端口**：本机没有旁路入口，命令只能来自 gate。
//
// 运行（先起 gate）：
//
//	go run ./examples/ops/cmd/agent -name web01 -addr localhost:8991 -root .
//
// -root 是工作目录根：cd 越出它会被拒（防从 Web 端逛到系统目录）。

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/w6xian/sloth/v4"
	"github.com/w6xian/sloth/v4/bucket"
	"github.com/w6xian/sloth/v4/option"
	"github.com/w6xian/sloth/v4/types/auth"

	"github.com/w6xian/sloth-proxy/examples/ops/internal/ops"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sloth.SetLogLevel("info")

	name := flag.String("name", "", "机器名（默认取 hostname），gate 侧用它寻址")
	addr := flag.String("addr", "localhost:8991", "gate 的 RPC 地址")
	network := flag.String("net", "tcp", "传输：tcp 或 quic（quic 强制 TLS，需证书）")
	root := flag.String("root", "", "允许的工作目录根；空=不限制（仅本地调试）")
	maxOut := flag.Int("max-output", 1<<20, "单条命令输出上限（字节）")
	flag.Parse()

	machine := *name
	if machine == "" {
		h, err := os.Hostname()
		if err != nil {
			sloth.Errorw(ctx, "get hostname failed", "err", err)
			return
		}
		machine = h
	}

	client := sloth.DefaultClient()
	conn := sloth.ClientConn(client)

	ex := ops.NewExecutor(ops.Options{AllowRoot: *root, MaxOutput: *maxOut})
	if err := conn.Register("ops", ops.NewService(ex), "ops executor"); err != nil {
		sloth.Errorw(ctx, "register ops service failed", "err", err)
		return
	}

	// 连接钩子：只维护"是否就绪"标志。
	//
	// 不能在 OnReady 里同步发 RPC——那时读写泵还没跑起来，会等不到回包
	// （见 sloth 客户端注释）。真正的 Sign/Reg 交给下面的后台循环。
	hook := &connHook{}
	if err := conn.Dial(ctx, *network, *addr,
		option.WithTcpClientHandleMessage(hook)); err != nil {
		sloth.Errorw(ctx, "dial gate failed", "addr", *addr, "err", err)
		return
	}
	defer conn.Close()

	// Sign（正数 userId）+ Reg（负数 userId，服务提供者）。
	// 连接重建后要重新来一遍：服务端 smap 与 bucket 里的 channel 是新连接了。
	register := func() error {
		data, err := client.Call(ctx, "v1.Sign", []byte("sign"))
		if err != nil {
			return err
		}
		ai := auth.AuthInfo{}
		if err := json.Unmarshal(data, &ai); err != nil {
			return err
		}
		if err := client.SetAuthInfo(&ai); err != nil {
			return err
		}
		// 注册带上 OS：gate 要按平台选规则集（Windows 用 PowerShell cmdlet 白名单）
		regData, err := json.Marshal(ops.RegInfo{Name: machine, OS: runtime.GOOS})
		if err != nil {
			return err
		}
		data, err = client.Call(ctx, "v1.Reg", regData)
		if err != nil {
			return err
		}
		info := auth.AuthInfo{}
		if err := json.Unmarshal(data, &info); err != nil {
			return err
		}
		sloth.Infow(ctx, "registered to gate", "machine", machine, "userId", info.UserId)
		return nil
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			if !hook.ready.Load() || hook.registered.Load() {
				continue
			}
			if err := register(); err != nil {
				sloth.Errorw(ctx, "register failed, will retry", "machine", machine, "err", err)
				continue
			}
			hook.registered.Store(true)
		}
	}()

	sloth.Infow(ctx, "agent started", "machine", machine, "addr", *addr, "network", *network,
		"root", *root, "powershell", ops.PowerShellExe())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	sloth.Infow(ctx, "agent stopping")
}

// connHook 客户端连接事件：只记状态，不做 RPC。
type connHook struct {
	ready      atomic.Bool
	registered atomic.Bool
}

func (h *connHook) OnConnect(ctx context.Context, addr string) error { return nil }

func (h *connHook) OnReady(ctx context.Context, ch bucket.IChannel) error {
	h.ready.Store(true)
	return nil
}

func (h *connHook) OnClose(ctx context.Context, ch bucket.IChannel) error {
	// 连接断了：下一次重连成功后要重新 Reg
	h.ready.Store(false)
	h.registered.Store(false)
	return nil
}

func (h *connHook) OnData(ctx context.Context, ch bucket.IChannel, msg []byte) error { return nil }

func (h *connHook) OnError(ctx context.Context, ch bucket.IChannel, err error) error {
	sloth.Errorw(ctx, "connection error", "err", err)
	return nil
}
