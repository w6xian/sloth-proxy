package main

// sloth-proxy 的 gate：Web 管控端。
//
// 一次"敲命令"的完整链路：
//
//	浏览器 ──POST /api/exec──▶ gate
//	                            ① 登录态取操作者（会话）
//	                            ② 授权：用户在**这台机器**上是什么档位
//	                            ③ 按档位取规则集，ParseLine 切 argv（拒绝 shell 语法）
//	                            ④ 策略引擎判定（默认拒绝）
//	                            ⑤ 审计落盘（放行与拒绝都要记）
//	                            ⑥ server.Call(userId, "ops.Exec", argv) → agent 执行
//	浏览器 ◀────────────────── 输出 + 退出码 + 判定结果
//
// 关键点：**没有 pty、不经 shell**。每条命令是一次独立的请求/响应 RPC，
// 因此可超时、可取消、可审计，也不需要任何流式隧道。
//
// 运行：
//
//	go run ./examples/ops/cmd/gate -users examples/ops/users.json -grants examples/ops/grants.json
//	go run ./examples/ops/cmd/agent -name web01
//	浏览器打开 http://localhost:8080/（默认账号 demo/demo）

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/w6xian/sloth/v4"
	"github.com/w6xian/sloth/v4/bucket"
	"github.com/w6xian/sloth/v4/option"
	"github.com/w6xian/sloth/v4/types"
	"github.com/w6xian/sloth/v4/types/auth"

	"github.com/w6xian/sloth-proxy/examples/ops/internal/audit"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/authn"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/authz"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/ops"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/policy"
)

//go:embed web/index.html
var webFS embed.FS

const (
	// sessionCookie 会话 cookie 名。
	sessionCookie = "sloth_proxy_sid"
	// sessionTTL 会话有效期。
	sessionTTL = 8 * time.Hour
	// callTimeout 单次下发的超时。命令是短任务，30s 足够；
	// 用 r.Context() 作父上下文，浏览器一关页面在途调用立刻取消。
	callTimeout = 30 * time.Second
)

// smap 机器名 -> userId：agent 连上来调 v1.Reg(name) 登记，拿到负数 userId。
var smap = sloth.NewSMap()

// mos 机器名 -> OS（runtime.GOOS）：agent 注册时上报，gate 按它选规则集。
// 没上报过的机器按 Linux 处理（最保守的那套）。
var mos sync.Map

var auditSeq uint64

// gate 管控端的全部依赖。
type gate struct {
	server *sloth.ClientRpc
	auth   authn.Authenticator
	sess   *authn.SessionStore
	grants *authz.Store
	rec    *audit.Recorder

	mu      sync.Mutex
	engines map[string]*policy.Engine // 档位@平台 → 规则引擎（编译一次，之后复用）
}

// engine 按档位 + 平台取规则引擎。
//
// 平台必须参与：Windows 上 ls/cat/grep 不存在，用 Linux 规则集判 Windows
// 机器会得到一堆"allow，但 exec: not found"。
func (g *gate) engine(level, platform string) (*policy.Engine, error) {
	key := level + "@" + platform
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.engines[key]; ok {
		return e, nil
	}
	e, err := policy.New(policy.RulesFor(level, platform))
	if err != nil {
		return nil, err
	}
	g.engines[key] = e
	return e, nil
}

// machineOS 机器上报的 OS；未知按 linux（最保守）。
func machineOS(machine string) string {
	if v, ok := mos.Load(machine); ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return policy.PlatformLinux
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sloth.SetLogLevel("info")

	rpcAddr := flag.String("rpc", "localhost:8991", "sloth RPC 监听地址")
	webAddr := flag.String("web", "localhost:8080", "Web 管控端地址")
	auditPath := flag.String("audit", "./audit.jsonl", "审计日志（JSONL，append-only）")
	network := flag.String("net", "tcp", "传输：tcp 或 quic")
	usersPath := flag.String("users", "users.json", "账号表（JSON），不存在时用内置 demo 账号")
	grantsPath := flag.String("grants", "grants.json", "授权表（JSON），不存在时默认 view 档")
	flag.Parse()

	users, err := loadUsers(*usersPath)
	if err != nil {
		sloth.Errorw(ctx, "load users failed", "err", err)
		return
	}
	grants, err := loadGrants(*grantsPath)
	if err != nil {
		sloth.Errorw(ctx, "load grants failed", "err", err)
		return
	}
	rec, err := audit.New(*auditPath, 1000)
	if err != nil {
		sloth.Errorw(ctx, "open audit log failed", "path", *auditPath, "err", err)
		return
	}
	defer rec.Close()

	g := &gate{
		auth:    users,
		sess:    authn.NewSessionStore(sessionTTL),
		grants:  grants,
		rec:     rec,
		engines: make(map[string]*policy.Engine),
	}

	// DefaultServer 返回的是 *sloth.ClientRpc：调用目标是**客户端**。
	server := sloth.DefaultServer()
	g.server = server
	drpc := sloth.ServerConn(server)
	if err := drpc.Register("v1", &RegService{}, ""); err != nil {
		sloth.Errorw(ctx, "register v1 failed", "err", err)
		return
	}
	if err := drpc.Listen(ctx, *network, *rpcAddr,
		option.WithTcpHandleMessage(&ConnHandler{})); err != nil {
		sloth.Errorw(ctx, "listen failed", "err", err)
		return
	}
	go func() {
		if err := drpc.Serve(); err != nil {
			sloth.Errorw(ctx, "serve exited", "err", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/login", g.serveLogin)
	mux.HandleFunc("/api/logout", g.serveLogout)
	mux.HandleFunc("/api/me", g.serveMe)
	mux.HandleFunc("/api/machines", g.requireLogin(g.serveMachines))
	mux.HandleFunc("/api/exec", g.requireLogin(g.serveExec))
	mux.HandleFunc("/api/rules", g.requireLogin(g.serveRules))
	mux.HandleFunc("/api/audit", g.requireLogin(g.serveAudit))

	srv := &http.Server{
		Addr:              *webAddr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		sloth.Infow(ctx, "gate started", "rpc", *rpcAddr, "web", *webAddr, "audit", *auditPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			sloth.Errorw(ctx, "web server exited", "err", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	shutdownCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	_ = srv.Shutdown(shutdownCtx)
	_ = drpc.Close()
}

// ── 登录 / 会话 ──

// ctxUserKey 请求上下文里存登录用户的键。
type ctxUserKey struct{}

func withUser(r *http.Request, u authn.User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUserKey{}, u))
}

func userFrom(r *http.Request) (authn.User, bool) {
	u, ok := r.Context().Value(ctxUserKey{}).(authn.User)
	return u, ok
}

// userOf 从 cookie 取会话用户。
func (g *gate) userOf(r *http.Request) (authn.User, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return authn.User{}, false
	}
	return g.sess.Get(c.Value)
}

// tokenOf 取会话 token（会话状态如 cwd 挂在 token 上）。
func tokenOf(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// requireLogin 登录校验中间件：未登录一律 401。
func (g *gate) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := g.userOf(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "未登录或会话已过期"})
			return
		}
		next(w, withUser(r, u))
	}
}

type meResp struct {
	OK     bool          `json:"ok"`
	User   authn.User    `json:"user,omitempty"`
	Grants []authz.Grant `json:"grants"`
	TTL    int64         `json:"ttl_seconds"`
}

// serveLogin 登录：校验口令 → 建会话 → 下发 HttpOnly cookie。
func (g *gate) serveLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := g.auth.Verify(body.User, body.Pass)
	if err != nil {
		// 不区分"用户不存在"与"口令错"：避免被用来枚举账号
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "用户名或口令错误"})
		return
	}
	token, err := g.sess.New(*u)
	if err != nil {
		http.Error(w, "session failed", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, meResp{OK: true, User: *u, Grants: g.grants.GrantsOf(u.Name), TTL: int64(sessionTTL.Seconds())})
}

// serveLogout 登出：删会话并清 cookie。
func (g *gate) serveLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		g.sess.Del(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, map[string]bool{"ok": true})
}

// serveMe 当前登录者与其授权。未登录返回 ok=false（不是 401，方便前端判断）。
func (g *gate) serveMe(w http.ResponseWriter, r *http.Request) {
	u, ok := g.userOf(r)
	if !ok {
		writeJSON(w, meResp{OK: false})
		return
	}
	writeJSON(w, meResp{OK: true, User: u, Grants: g.grants.GrantsOf(u.Name)})
}

// ── 页面与业务 API ──

// serveIndex 终端页面。
func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

type machineInfo struct {
	Name   string `json:"name"`
	UserID int64  `json:"user_id"`
	Level  string `json:"level"`
	OS     string `json:"os"`
}

// serveMachines 只返回**当前用户有授权**的机器。
//
// 没授权的机器不列出来：列表本身就是信息，不该让任何人看到全量拓扑。
func (g *gate) serveMachines(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r)
	all := make([]string, 0, smap.Len())
	for name := range smap.Range() {
		all = append(all, name)
	}
	allowed := g.grants.Filter(u.Name, all)
	sort.Strings(allowed)
	out := make([]machineInfo, 0, len(allowed))
	for _, name := range allowed {
		uid, _ := smap.Get(name)
		level, _ := g.grants.Level(u.Name, name)
		out = append(out, machineInfo{Name: name, UserID: uid, Level: level, OS: machineOS(name)})
	}
	writeJSON(w, out)
}

// execBody /api/exec 的请求体。
type execBody struct {
	Machine string `json:"machine"`
	Line    string `json:"line"`
	Cwd     string `json:"cwd"`
}

// execResult /api/exec 的响应：输出 + 判定 + 审计要点。
type execResult struct {
	OK        bool   `json:"ok"`
	Denied    bool   `json:"denied"`
	Decision  string `json:"decision"`
	Level     string `json:"level,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Output    string `json:"output,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	OutputID  string `json:"output_id,omitempty"`
	CostMS    int64  `json:"cost_ms"`
	Error     string `json:"error,omitempty"`
	Cwd       string `json:"cwd,omitempty"` // 会话当前目录（cd/pwd 与执行后回带）
}

// serveExec 执行一次命令：授权 → 策略 → 审计 → 下发。
func (g *gate) serveExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var body execBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	u, _ := userFrom(r)
	ent := audit.Entry{
		ID:      fmt.Sprintf("a%d-%d", time.Now().UnixNano(), atomic.AddUint64(&auditSeq, 1)),
		Time:    time.Now(),
		User:    u.Name,
		Machine: body.Machine,
		Line:    body.Line,
	}
	begin := time.Now()

	// ① 授权：这台机器给不给这个人用（没授权与机器不存在返回同一句话）
	level, granted := g.grants.Level(u.Name, body.Machine)
	if !granted {
		ent.Decision = string(policy.Deny)
		ent.RuleID = "no-grant"
		ent.Reason = "该机器未授权"
		ent.CostMS = time.Since(begin).Milliseconds()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{
			Denied:   true,
			Decision: string(policy.Deny),
			RuleID:   "no-grant",
			Reason:   "该机器未授权",
		})
		return
	}
	ent.Level = level
	platform := machineOS(body.Machine)

	// 判定**统一用 Linux 规则集**：不管 agent 是 Linux 还是 Windows，
	// 人敲的都是 Linux 命令。平台只影响"下发前怎么翻译"。
	eng, err := g.engine(level, policy.PlatformLinux)
	if err != nil {
		http.Error(w, "policy error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// ② 切 argv：含 shell 元字符直接拒（这是白名单能拦住的前提）
	argv, perr := policy.ParseLine(body.Line)
	if perr != nil {
		ent.Decision = string(policy.Deny)
		ent.RuleID = "parse"
		ent.Reason = perr.Error()
		ent.CostMS = time.Since(begin).Milliseconds()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Level: level, Decision: string(policy.Deny), RuleID: "parse", Reason: perr.Error()})
		return
	}
	ent.Argv = argv

	// ③ 策略判定（默认拒绝）
	v := eng.Check(argv)
	ent.Decision = string(v.Decision)
	ent.RuleID = v.RuleID
	ent.Reason = v.Reason
	if v.Decision != policy.Allow {
		ent.CostMS = time.Since(begin).Milliseconds()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{
			Denied:   true,
			Decision: string(v.Decision),
			Level:    level,
			RuleID:   v.RuleID,
			Reason:   v.Reason,
		})
		return
	}

	// ④ 找到机器对应的连接
	userID, ok := smap.Get(body.Machine)
	if !ok {
		ent.Error = "machine not registered"
		ent.CostMS = time.Since(begin).Milliseconds()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{
			Decision: string(policy.Allow),
			Level:    level,
			Error:    "机器未登记或未在线",
		})
		return
	}

	// ⑤ 会话内置命令（cd / pwd / help）：不下发，只动会话状态 + 问一次 agent 的路径校验
	if policy.IsBuiltin(argv) {
		if argv[0] == "help" {
			ent.CostMS = time.Since(begin).Milliseconds()
			_ = g.rec.Record(ent)
			writeJSON(w, execResult{OK: true, Decision: string(policy.Allow), Level: level,
				Output: "这台机器上敲 help 时，终端会直接列出允许的命令；也可看右侧规则集"})
			return
		}
		g.serveBuiltin(w, r, body.Machine, userID, argv, ent, begin)
		return
	}

	// ⑥ Windows：把 Linux 命令翻成 PowerShell 等价命令，再复核一遍产物
	sendArgv := argv
	if policy.IsWindows(platform) {
		winArgv, terr := policy.Translate(argv)
		if terr != nil {
			ent.Decision = string(policy.Deny)
			ent.RuleID = "no-windows-equivalent"
			ent.Reason = terr.Error()
			ent.CostMS = time.Since(begin).Milliseconds()
			_ = g.rec.Record(ent)
			writeJSON(w, execResult{
				Denied:   true,
				Decision: string(policy.Deny),
				Level:    level,
				RuleID:   "no-windows-equivalent",
				Reason:   terr.Error(),
			})
			return
		}
		// 复核：翻译模板里不能有白名单之外的命令（含管道每一段）
		winEng, err := g.engine(level, platform)
		if err != nil {
			http.Error(w, "policy error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := policy.CheckPipeline(winEng, winArgv); err != nil {
			ent.Decision = string(policy.Deny)
			ent.RuleID = "translate-rejected"
			ent.Reason = err.Error()
			ent.CostMS = time.Since(begin).Milliseconds()
			_ = g.rec.Record(ent)
			writeJSON(w, execResult{
				Denied:   true,
				Decision: string(policy.Deny),
				Level:    level,
				RuleID:   "translate-rejected",
				Reason:   err.Error(),
			})
			return
		}
		sendArgv = winArgv
	}

	// ⑦ 下发执行
	payload, _ := json.Marshal(ops.ExecReq{
		Argv:      sendArgv,
		Cwd:       g.sess.Cwd(tokenOf(r), body.Machine),
		TimeoutMs: int(callTimeout.Milliseconds()),
	})
	callCtx, stop := context.WithTimeout(r.Context(), callTimeout)
	defer stop()
	raw, err := g.server.Call(callCtx, userID, ops.MethodExec, payload)
	ent.CostMS = time.Since(begin).Milliseconds()
	if err != nil {
		ent.Error = err.Error()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Decision: string(policy.Allow), Level: level, Error: err.Error()})
		return
	}
	var er ops.ExecResp
	if err := json.Unmarshal(raw, &er); err != nil {
		ent.Error = "bad exec response: " + err.Error()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Decision: string(policy.Allow), Level: level, Error: ent.Error})
		return
	}
	ent.ExitCode = er.ExitCode
	ent.Bytes = er.Bytes
	ent.OutputID = er.OutputID
	ent.Error = er.Error
	_ = g.rec.Record(ent)

	writeJSON(w, execResult{
		OK:        er.Error == "" && er.ExitCode == 0,
		Decision:  string(policy.Allow),
		Level:     level,
		Output:    er.Output,
		ExitCode:  er.ExitCode,
		Bytes:     er.Bytes,
		Truncated: er.Truncated,
		OutputID:  er.OutputID,
		CostMS:    er.CostMS,
		Error:     er.Error,
	})
}

// serveBuiltin 处理 cd / pwd：这两个是 shell 内置，exec 里没有对应的可执行文件。
//
// 做法：cwd 记在**会话**（用户 × 机器）里，cd 只改状态、不下发任何命令。
// 越界判断不放在 gate——它不知道 agent 的 -root，另写一套路径规则必然与
// agent 不一致（两边都判 = 两套真相）。交给 agent 的 ops.Resolve：
// 它才是真正知道边界的那个人，而且只回路径、不起进程。
func (g *gate) serveBuiltin(w http.ResponseWriter, r *http.Request, machine string, userID int64,
	argv []string, ent audit.Entry, begin time.Time) {
	token := tokenOf(r)
	cur := g.sess.Cwd(token, machine)

	// pwd：会话里已有就直接用，省一次 RPC
	if argv[0] == "pwd" && cur != "" {
		ent.CostMS = time.Since(begin).Milliseconds()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{OK: true, Decision: string(policy.Allow), Level: ent.Level, Output: cur, Cwd: cur})
		return
	}

	target := ""
	if len(argv) > 1 {
		target = strings.Join(argv[1:], " ")
	}
	payload, _ := json.Marshal(ops.ResolveReq{Base: cur, Path: target})
	callCtx, stop := context.WithTimeout(r.Context(), callTimeout)
	defer stop()
	raw, err := g.server.Call(callCtx, userID, ops.MethodResolve, payload)
	ent.CostMS = time.Since(begin).Milliseconds()
	if err != nil {
		ent.Error = err.Error()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Decision: string(policy.Allow), Level: ent.Level, Error: err.Error(), Cwd: cur})
		return
	}
	var rr ops.ResolveResp
	if err := json.Unmarshal(raw, &rr); err != nil {
		ent.Error = "bad resolve response: " + err.Error()
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Decision: string(policy.Allow), Level: ent.Level, Error: ent.Error, Cwd: cur})
		return
	}
	if rr.Error != "" {
		ent.ExitCode = 1
		ent.Error = rr.Error
		_ = g.rec.Record(ent)
		writeJSON(w, execResult{Decision: string(policy.Allow), Level: ent.Level, ExitCode: 1, Error: rr.Error, Cwd: cur})
		return
	}
	g.sess.SetCwd(token, machine, rr.Cwd)
	_ = g.rec.Record(ent)
	writeJSON(w, execResult{OK: true, Decision: string(policy.Allow), Level: ent.Level, Output: rr.Cwd, Cwd: rr.Cwd})
}

// ── 能执行哪些命令 ──

// rulesResp /api/rules 的响应：某台机器上、你这个档位能干什么。
type rulesResp struct {
	Machine  string        `json:"machine"`
	Level    string        `json:"level"`
	Platform string        `json:"platform"`
	Granted  bool          `json:"granted"`
	Levels   []string      `json:"levels"`
	Allow    []policy.Rule `json:"allow"`
	Deny     []policy.Rule `json:"deny"`
	Note     string        `json:"note"`
	// Mappings 只在 Windows 机器上给：敲的是 Linux 命令，实际跑的是下面这些
	Mappings []policy.Mapping `json:"mappings,omitempty"`
}

// serveRules 返回当前用户在指定机器上的档位及其规则集——即"支持哪些命令"。
//
// 这是**只读**的元信息，只对已授权机器返回；未授权机器只答"未授权"。
// 让人看到白名单，比让他一条条试、然后在审计里留一堆试探记录要好。
func (g *gate) serveRules(w http.ResponseWriter, r *http.Request) {
	u, _ := userFrom(r)
	machine := r.URL.Query().Get("machine")
	level, granted := g.grants.Level(u.Name, machine)
	platform := machineOS(machine)
	resp := rulesResp{
		Machine:  machine,
		Platform: platform,
		Granted:  granted,
		Levels:   []string{policy.LevelView, policy.LevelOps, policy.LevelAdmin},
		Note:     "默认拒绝：不在 allow 里的命令一律拦截；; | & $() 等 shell 语法在解析阶段直接拒",
	}
	if !granted {
		resp.Note = "该机器未授权"
		writeJSON(w, resp)
		return
	}
	resp.Level = level
	if policy.IsWindows(platform) {
		resp.Note = "入口统一是 Linux 命令；下发前会翻译成右列的 Windows 命令，翻译产物还要过一遍独立白名单"
		resp.Mappings = policy.Mappings()
	}
	for _, rule := range policy.RulesFor(level, platform) {
		if rule.Effect == policy.Allow {
			resp.Allow = append(resp.Allow, rule)
		} else {
			resp.Deny = append(resp.Deny, rule)
		}
	}
	writeJSON(w, resp)
}

// serveAudit 最近 n 条审计（倒序）。
func (g *gate) serveAudit(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 50
	}
	writeJSON(w, g.rec.Recent(n))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// ── sloth 服务端 ──

// RegService 服务端侧的注册服务：Sign（普通连接）+ Reg（服务提供者）。
type RegService struct{}

// Sign 把连接放进 bucket（正数 userId）。
func (RegService) Sign(ctx context.Context, data []byte) ([]byte, error) {
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
		Token:  "token_ops",
		Ts:     time.Now().Unix(),
	}
	svr.Bucket(ai.UserId).Put(ai.UserId, ai.RoomId, ai.Token, ch)
	return json.Marshal(ai)
}

// Reg 把连接登记成服务提供者：分配负数 userId，gate 按机器名找到它。
//
// payload 是 ops.RegInfo 的 JSON；老格式（裸机器名）也兼容，按 Linux 处理。
func (RegService) Reg(ctx context.Context, payload string) ([]byte, error) {
	info := ops.RegInfo{Name: strings.TrimSpace(payload)}
	if err := json.Unmarshal([]byte(payload), &info); err != nil || info.Name == "" {
		info = ops.RegInfo{Name: strings.TrimSpace(payload)}
	}
	name := info.Name
	if name == "" {
		return nil, errors.New("empty machine name")
	}
	if info.OS != "" {
		mos.Store(name, info.OS)
	}
	ch, err := sloth.GetChannel(ctx)
	if err != nil {
		return nil, err
	}
	svr, err := sloth.GetBucket(ctx)
	if err != nil {
		return nil, err
	}
	svrID, err := smap.Reg(name, false)
	if err != nil {
		return nil, err
	}
	ai := auth.AuthInfo{
		UserId: svrID,
		RoomId: -1, // 服务型连接不进房间，避免被广播误伤
		Token:  "token_" + name,
		Ts:     time.Now().Unix(),
	}
	svr.Bucket(ai.UserId).Put(ai.UserId, ai.RoomId, ai.Token, ch)
	sloth.Infow(ctx, "machine registered", "machine", name, "userId", svrID, "os", info.OS)
	return json.Marshal(ai)
}

// ConnHandler 服务端连接钩子：只打日志。
type ConnHandler struct{}

func (ConnHandler) OnConnect(ctx context.Context, addr string) error {
	sloth.Infow(ctx, "agent connected", "remote", addr)
	return nil
}

func (ConnHandler) OnReady(ctx context.Context, s types.IBucket, ch bucket.IChannel) error {
	return nil
}

func (ConnHandler) OnData(ctx context.Context, s types.IBucket, ch bucket.IChannel, msg []byte) error {
	return nil
}

func (ConnHandler) OnClose(ctx context.Context, s types.IBucket, ch bucket.IChannel) error {
	sloth.Infow(ctx, "agent disconnected", "userId", ch.UserId())
	return nil
}

func (ConnHandler) OnError(ctx context.Context, s types.IBucket, ch bucket.IChannel, err error) error {
	sloth.Errorw(ctx, "agent connection error", "userId", ch.UserId(), "err", err)
	return nil
}
