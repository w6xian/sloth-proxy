package main

// 客户端（内网侧）示例：把本地目录暴露出去，并支持上传。
//
// 它做三件事：
//  1. 用 Forward 把本地的 http.Handler 包成转发服务并注册成 "http.Do"；
//  2. 连上服务端，在**每次连接就绪**时（含断线重连后）重新 Sign / Reg；
//  3. 本地 Handler 提供三样东西：目录浏览（FileServer）、文件列表、分片上传。
//
// Range / 206 / Content-Type / MIME / 304 全部由 http.FileServer 提供——
// 注意这里**没有起本地 HTTP 服务**：Forward 直接调 Handler，不占端口。
//
// 运行（先起 examples/media/server）：
//
//	go run ./examples/media/client -root ./.media

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/w6xian/sloth/v4"
	"github.com/w6xian/sloth/v4/bucket"
	"github.com/w6xian/sloth/v4/option"
	"github.com/w6xian/sloth/v4/types/auth"
	"github.com/w6xian/tlv"

	proxy "github.com/w6xian/sloth-proxy"
	proxyhttp "github.com/w6xian/sloth-proxy/http"
)

const (
	defaultRpcAddr = "localhost:8991"
	// serviceName 网关 URL 里的服务名：/m/media/...
	serviceName = "media"

	// uploadChunkMax 单片上限。请求报文走 RPC 入参，受 ag 编码单参数
	// ≤ 65535 字节限制，网关侧还会再卡一道（默认 60000）。
	// 前端按 48KB 切片，这里放宽到 56KB 只是兜底。
	uploadChunkMax = 56 << 10
)

var rpcAddr = defaultRpcAddr

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sloth.SetLogLevel("info")

	root := flag.String("root", "./.media", "对外暴露的本地目录")
	flag.StringVar(&rpcAddr, "rpc", defaultRpcAddr, "服务端 RPC 地址")
	flag.Parse()

	if err := prepareRoot(*root); err != nil {
		sloth.Errorw(ctx, "prepare root failed", "err", err)
		return
	}

	c := &clientApp{
		root:   *root,
		client: sloth.DefaultClient(),
	}
	conn := sloth.ClientConn(c.client)

	// ① 注册转发服务：服务端网关调 "http.Do" 时走到 Forwarder.Do。
	//    这里用本地目录的 mux（浏览 + 列表 + 上传），换成自己的 http.Handler
	//    就是代理自己的服务。
	fwd := proxyhttp.Forward(rootHandler(*root), proxyhttp.WithLogger(proxy.SlothLogger()))
	if err := conn.Register(proxyhttp.Service, fwd, ""); err != nil {
		sloth.Errorw(ctx, "register service failed", "err", err)
		return
	}

	// ② 连服务端。TCP 客户端自带重连（见 sloth 的 nrpc/tcp）：
	//    - 服务器还没起来 → 后台按 500ms→30s 退避重试，起来后自动连上；
	//    - 连上之后被断掉 → 立刻重连。
	//    每次连接就绪都会回调 OnReady，注册就放在那里做。
	h := &clientHandler{register: c.register}
	if err := conn.Dial(ctx, sloth.TCP, rpcAddr,
		option.WithTcpClientHandleMessage(h)); err != nil {
		// 现在连不上不代表失败：后台还在等服务器。这里只提示，不退出。
		sloth.Infow(ctx, "server not reachable yet, waiting in background",
			"addr", rpcAddr, "err", err)
	}
	defer conn.Close()

	// 等退出信号。**不要**写 select {}（空 select 永久阻塞）：一旦连接断开、
	// 重连又在退避等待里，运行时会判定"所有 goroutine 都睡着了"直接 fatal。
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	sloth.Infow(ctx, "shutdown signal received")
}

// clientApp 客户端的运行时状态。
type clientApp struct {
	root   string
	client *sloth.ServerRpc
}

// register 向服务端登记身份：Sign 拿正数 userId（收推送），
// Reg 拿负数 userId（当服务提供者，网关按服务名找它）。
//
// 必须在**每次**连接就绪后重做一次：重连后是新连接，服务端 bucket 里挂的
// 还是旧 channel，不重新 Reg 的话网关调不过来。
func (c *clientApp) register(ctx context.Context) {
	for i := 1; i <= 5; i++ {
		data, err := c.client.Call(ctx, "v1.Sign", []byte("sign"))
		if err != nil {
			sloth.Errorw(ctx, "sign failed", "attempt", i, "err", err)
			time.Sleep(time.Second)
			continue
		}
		ai := &auth.AuthInfo{}
		if err := tlv.Json2Struct(data, ai); err != nil {
			sloth.Errorw(ctx, "sign decode failed", "err", err)
			time.Sleep(time.Second)
			continue
		}
		if err := c.client.SetAuthInfo(ai); err != nil {
			sloth.Errorw(ctx, "set auth info failed", "err", err)
			time.Sleep(time.Second)
			continue
		}

		data, err = c.client.Call(ctx, "v1.Reg", serviceName)
		if err != nil {
			sloth.Errorw(ctx, "reg failed", "attempt", i, "err", err)
			time.Sleep(time.Second)
			continue
		}
		info := &auth.AuthInfo{}
		if err := tlv.Json2Struct(data, info); err != nil {
			sloth.Errorw(ctx, "reg decode failed", "err", err)
			time.Sleep(time.Second)
			continue
		}
		sloth.Infow(ctx, "registered", "service", serviceName, "userId", info.UserId,
			"hint", "curl -r 0-99 http://localhost:8080/m/"+serviceName+"/sample.bin")
		return
	}
	sloth.Errorw(ctx, "give up registering, will retry after reconnect")
}

// clientHandler 客户端的连接事件回调。
type clientHandler struct {
	register func(context.Context)
}

func (h *clientHandler) OnConnect(ctx context.Context, addr string) error {
	sloth.Infow(ctx, "connected to server", "addr", addr)
	return nil
}

// OnReady 连接就绪。注意这里**不能同步发 RPC**：读写循环（pump）还没跑起来，
// 同步调用会等不到回包。所以另起 goroutine 去注册。
func (h *clientHandler) OnReady(ctx context.Context, ch bucket.IChannel) error {
	sloth.Infow(ctx, "connection ready, registering", "userId", ch.UserId())
	go h.register(context.Background())
	return nil
}

func (h *clientHandler) OnData(ctx context.Context, ch bucket.IChannel, msg []byte) error {
	return nil
}

func (h *clientHandler) OnClose(ctx context.Context, ch bucket.IChannel) error {
	sloth.Infow(ctx, "connection closed, waiting for auto reconnect")
	return nil
}

func (h *clientHandler) OnError(ctx context.Context, ch bucket.IChannel, err error) error {
	sloth.Errorw(ctx, "connection error", "err", err)
	return nil
}

// rootHandler 本地对外暴露的东西：目录浏览 + 文件列表 + 分片上传。
func rootHandler(root string) http.Handler {
	mux := http.NewServeMux()
	// 下载/浏览：Range / MIME / 304 全是 FileServer 的现成能力
	mux.Handle("/", http.FileServer(http.Dir(root)))
	// 上传：前端切片后逐片 POST 到这里
	mux.HandleFunc("/_upload", uploadHandler(root))
	// 列表：给 web UI 用的 JSON
	mux.HandleFunc("/_list", listHandler(root))
	return mux
}

// uploadHandler 接收一个分片并写到指定偏移。
//
// POST /_upload?name=xxx&offset=N，body 是这一片的原始字节。
// offset=0 会截断已存在的文件（重传从零开始），其余按偏移追加。
func uploadHandler(root string) http.HandlerFunc {
	rootClean := filepath.Clean(root)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := r.URL.Query().Get("name")
		offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if name == "" || err != nil || offset < 0 {
			http.Error(w, "bad name or offset", http.StatusBadRequest)
			return
		}
		// 防路径穿越：不管 name 里写什么，落点都必须在 root 之内
		target := filepath.Join(rootClean, filepath.Clean("/"+name))
		if target != rootClean && !strings.HasPrefix(target, rootClean+string(filepath.Separator)) {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, uploadChunkMax+1))
		if err != nil {
			http.Error(w, "read body", http.StatusInternalServerError)
			return
		}
		if int64(len(body)) > uploadChunkMax {
			http.Error(w, "chunk too large", http.StatusRequestEntityTooLarge)
			return
		}

		flag := os.O_CREATE | os.O_WRONLY
		if offset == 0 {
			flag |= os.O_TRUNC // 从零开始 = 覆盖旧文件
		}
		f, err := os.OpenFile(target, flag, 0o644)
		if err != nil {
			http.Error(w, "open file", http.StatusInternalServerError)
			return
		}
		if _, err := f.WriteAt(body, offset); err != nil {
			f.Close()
			http.Error(w, "write file", http.StatusInternalServerError)
			return
		}
		f.Close()

		sloth.Infow(r.Context(), "uploaded chunk", "name", name,
			"offset", offset, "bytes", len(body))
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "ok %d", offset+int64(len(body)))
	}
}

// listHandler 返回目录里的文件（给 web UI 用）。
func listHandler(root string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := os.ReadDir(root)
		if err != nil {
			http.Error(w, "read dir", http.StatusInternalServerError)
			return
		}
		type item struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			Mod  int64  `json:"mod"`
			Dir  bool   `json:"dir"`
		}
		out := make([]item, 0, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				continue
			}
			out = append(out, item{
				Name: e.Name(), Size: info.Size(),
				Mod: info.ModTime().Unix(), Dir: e.IsDir(),
			})
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// prepareRoot 准备示例文件：真实使用时把 -root 指向自己的目录即可。
func prepareRoot(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"),
		[]byte("hello from the intranet\n"), 0o644); err != nil {
		return err
	}
	// sample.bin 1MB，内容可预测（i%251），方便用 Range 校验字节是否正确
	return writeOnce(filepath.Join(root, "sample.bin"), 1<<20, func(w *os.File) error {
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = byte(i % 251)
		}
		_, err := w.Write(buf)
		return err
	})
}

// writeOnce 目标文件不存在时才写入。
func writeOnce(path string, size int64, write func(*os.File) error) error {
	if st, err := os.Stat(path); err == nil && st.Size() == size {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return write(f)
}
