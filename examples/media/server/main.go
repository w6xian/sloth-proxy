package main

// 服务端（外网侧）示例：起 sloth 监听 + HTTP 网关。
//
// 网关把 /m/{svc}/{path...} 打到内网客户端上，客户端用本地的
// http.FileServer 提供 Range / MIME / 304，网关只负责搬运。
//
// 运行：
//
//	go run ./examples/media/server   # RPC 8991 + 网关 8080
//	go run ./examples/media/client    # 连上来，把本地目录暴露成 /m/media/
//	curl.exe -r 0-99 http://localhost:8080/m/media/sample.bin -D -

import (
	"context"
	"embed"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/w6xian/sloth/v4"
	"github.com/w6xian/sloth/v4/bucket"
	"github.com/w6xian/sloth/v4/option"
	"github.com/w6xian/sloth/v4/types"
	"github.com/w6xian/sloth/v4/types/auth"
	"github.com/w6xian/tlv"

	proxy "github.com/w6xian/sloth-proxy"
	proxyhttp "github.com/w6xian/sloth-proxy/http"
)

// 默认端口；都能用 flag 改，方便本机同时跑多份（-rpc :9091 -gw :8081）。
const (
	defaultRpcAddr     = "localhost:8991"
	defaultGatewayAddr = "localhost:8080"
)

var (
	rpcAddr     = defaultRpcAddr
	gatewayAddr = defaultGatewayAddr
)

// smap 服务名 -> userId 的登记表。客户端连上来调 v1.Reg(name) 把自己登记成
// 服务提供者，拿到**负数** userId，与 Sign 分给普通客户端的正数 ID 不冲突。
// 网关据此把 /m/{svc}/... 路由到对应的连接。
var smap = sloth.NewSMap()

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flag.StringVar(&rpcAddr, "rpc", defaultRpcAddr, "RPC 监听地址")
	flag.StringVar(&gatewayAddr, "gw", defaultGatewayAddr, "HTTP 网关地址")
	flag.Parse()

	sloth.SetLogLevel("info")

	// DefaultServer 返回 *ClientRpc：调用目标是**客户端**（名字里的 Client 指目标）。
	// 网关正是靠它把请求打到内网客户端上。
	server := sloth.DefaultServer()
	drpc := sloth.ServerConn(server)

	if err := drpc.Register("v1", &HelloService{}, ""); err != nil {
		sloth.Errorw(ctx, "register service failed", "err", err)
		return
	}

	// 媒体走 tcp：fn 帧 Length 是 uint32、上限 1GB，且响应不 base64。
	// ws 那边还有一层 DataSlice 分片（T/I 是 byte，≤256 片），大块不划算。
	if err := drpc.Listen(ctx, sloth.TCP, rpcAddr,
		option.WithTcpHandleMessage(&Handler{})); err != nil {
		sloth.Errorw(ctx, "listen failed", "err", err)
		return
	}
	go func() {
		if err := drpc.Serve(); err != nil {
			sloth.Errorw(ctx, "serve exited", "err", err)
		}
	}()

	// 网关本身只是个 http.Handler：起不起、起在哪个端口是这里的事
	// （库不做"非主动，不执行"之外的任何动作）。
	gw := proxyhttp.NewGateway(server, smap, proxyhttp.WithLogger(proxy.SlothLogger()))
	mux := http.NewServeMux()
	mux.Handle("/m/{svc}/{path...}", proxyhttp.Auth(gw, allowAll))
	mux.HandleFunc("/", index)

	gsrv := &http.Server{
		Addr:              gatewayAddr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		sloth.Infow(ctx, "gateway started", "addr", gatewayAddr,
			"hint", "curl -r 0-99 http://"+gatewayAddr+"/m/media/sample.bin")
		if err := gsrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sloth.Errorw(ctx, "gateway exited", "err", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	sloth.Infow(ctx, "shutdown signal received")

	if err := drpc.Close(); err != nil {
		sloth.Errorw(ctx, "close server failed", "err", err)
	}
	stopCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := gsrv.Shutdown(stopCtx); err != nil {
		sloth.Errorw(ctx, "shutdown gateway failed", "err", err)
	}
}

func allowAll(*http.Request) bool { return true }

//go:embed page.html
var demoPage embed.FS

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := demoPage.ReadFile("page.html")
	if err != nil {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// Handler TCP 的连接生命周期回调。
type Handler struct{}

func (h *Handler) OnConnect(ctx context.Context, addr string) error {
	sloth.Infow(ctx, "client connected", "remote", addr)
	return nil
}

func (h *Handler) OnReady(ctx context.Context, s types.IBucket, ch bucket.IChannel) error {
	sloth.Infow(ctx, "connection ready", "userId", ch.UserId())
	return nil
}

func (h *Handler) OnData(ctx context.Context, s types.IBucket, ch bucket.IChannel, msg []byte) error {
	return nil
}

func (h *Handler) OnClose(ctx context.Context, s types.IBucket, ch bucket.IChannel) error {
	sloth.Infow(ctx, "connection closed", "userId", ch.UserId())
	return nil
}

func (h *Handler) OnError(ctx context.Context, s types.IBucket, ch bucket.IChannel, err error) error {
	sloth.Errorw(ctx, "connection error", "userId", ch.UserId(), "err", err)
	return nil
}

// HelloService 服务端侧的 RPC 服务：Sign（普通客户端）与 Reg（服务提供者）。
type HelloService struct{}

// Sign 把连接登记进 bucket（正数 userId），之后服务端可按 userId 主动推消息。
func (h *HelloService) Sign(ctx context.Context, data []byte) ([]byte, error) {
	ch, err := sloth.GetChannel(ctx)
	if err != nil {
		return nil, err
	}
	svr, err := sloth.GetBucket(ctx)
	if err != nil {
		return nil, err
	}
	ai := auth.AuthInfo{
		UserId: 1,
		RoomId: 1,
		Token:  "token_media",
		Ts:     time.Now().Unix(),
	}
	svr.Bucket(ai.UserId).Put(ai.UserId, ai.RoomId, ai.Token, ch)
	return tlv.Json(ai), nil
}

// Reg 把连接登记成服务提供者：分配**负数** userId，之后网关按服务名找到它。
// RoomId 用 -1：服务型连接不进房间，不会被 CallRoom 的广播误伤。
func (h *HelloService) Reg(ctx context.Context, name string) ([]byte, error) {
	ch, err := sloth.GetChannel(ctx)
	if err != nil {
		return nil, err
	}
	svr, err := sloth.GetBucket(ctx)
	if err != nil {
		return nil, err
	}
	svrId, err := smap.Reg(name, false)
	if err != nil {
		return nil, err
	}
	ai := auth.AuthInfo{
		UserId: svrId,
		RoomId: -1,
		Token:  "token_" + name,
		Ts:     time.Now().Unix(),
	}
	svr.Bucket(ai.UserId).Put(ai.UserId, ai.RoomId, ai.Token, ch)
	sloth.Infow(ctx, "service registered", "service", name, "userId", svrId)
	return tlv.Json(ai), nil
}
