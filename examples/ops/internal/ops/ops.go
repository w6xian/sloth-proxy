// Package ops 是 agent 侧的执行器与 RPC 服务。
//
// 设计要点：
//  1. 命令以 argv 传入，**绝不经 shell**（白名单能拦得住的前提）；
//  2. 输出不整包走 RPC 返回：先落本地缓存，回包只带前缀，剩下的用
//     ops.Output(id, offset, len) 分片取（与媒体代理的 Range 同一个思路）；
//  3. 超时必须**杀掉整个进程组**：ctx 取消只会结束 Wait，不会停子进程。
package ops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 方法名：gate 侧用 "ops.Exec" / "ops.Output" 反调 agent。
const (
	MethodExec    = "ops.Exec"
	MethodOutput  = "ops.Output"
	MethodResolve = "ops.Resolve"
)

const (
	maxOutputBytes = 1 << 20  // 单次输出上限，超出截断
	previewBytes   = 8 << 10  // 回包里直接带的前缀
	chunkMaxBytes  = 32 << 10 // 单次 Output 分片上限
	keepOutputs    = 32       // 输出缓存条数（超出淘汰最旧）
	defaultTimeout = 10 * time.Second
)

// ExecReq 执行请求。
type ExecReq struct {
	Argv      []string `json:"argv"`
	Cwd       string   `json:"cwd"`
	TimeoutMs int      `json:"timeout_ms"`
}

// ExecResp 执行结果。Output 只是前缀，完整输出用 Output 方法按分片取。
type ExecResp struct {
	OutputID  string `json:"output_id"`
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	CostMS    int64  `json:"cost_ms"`
	Error     string `json:"error,omitempty"`
}

// RegInfo agent 注册时上报给 gate 的信息。
//
// OS 决定 gate 用哪套规则集：Windows 上没有 ls/cat/grep，白名单必须对
// PowerShell cmdlet。不带上它，gate 只能猜——猜错就是"allow 但 not found"。
type RegInfo struct {
	Name string `json:"name"`
	OS   string `json:"os"` // runtime.GOOS
}

// ResolveReq 解析 cd 目标：base 是当前目录，path 是目标（相对或绝对）。
type ResolveReq struct {
	Base string `json:"base"`
	Path string `json:"path"`
}

// ResolveResp 解析结果：只回路径，不执行任何东西。
type ResolveResp struct {
	Cwd   string `json:"cwd"`
	Error string `json:"error,omitempty"`
}

// OutputReq 取输出分片。
type OutputReq struct {
	OutputID string `json:"output_id"`
	Offset   int    `json:"offset"`
	Length   int    `json:"length"`
}

// OutputResp 输出分片。
type OutputResp struct {
	Offset int    `json:"offset"`
	Data   string `json:"data"`
	Total  int    `json:"total"`
	EOF    bool   `json:"eof"`
}

// Options 执行器配置。
type Options struct {
	// AllowRoot 允许的工作目录根：cwd 超出它即拒绝。
	// 空表示不限制——仅本地调试用，生产必须设。
	AllowRoot string
	// MaxOutput 单条输出上限，0 用默认值。
	MaxOutput int
}

// Executor 执行器：跑命令 + 缓存输出供分片读取。
type Executor struct {
	allowRoot string
	maxOutput int

	mu      sync.Mutex
	outputs map[string]*blob
	order   []string
	seq     uint64
}

type blob struct {
	data []byte
	at   time.Time
}

// NewExecutor 创建执行器。
func NewExecutor(opt Options) *Executor {
	maxOutput := opt.MaxOutput
	if maxOutput <= 0 {
		maxOutput = maxOutputBytes
	}
	return &Executor{
		allowRoot: opt.AllowRoot,
		maxOutput: maxOutput,
		outputs:   make(map[string]*blob, keepOutputs),
	}
}

// buildArgv Windows 上把 argv 包成一次 PowerShell 调用。
//
// 为什么必须包：Windows 没有 ls/cat/grep/head/tail 这些可执行文件，
// dir/type/echo 又是 cmd 的内置命令（不是 exe，exec.Command 找不到），
// 所以只能用 PowerShell cmdlet——白名单在 Windows 上对的就是
// Get-ChildItem / Get-Content / Select-String 这一族。
//
// 安全性**不靠这层包装**，靠上游两道闸：
//  1. gate 侧策略引擎已按 Windows 规则集判定过 argv（默认拒绝）；
//  2. ParseLine 拒绝 ; | & $ ` () <> 等元字符，拼进 -Command 的字符串
//     里不存在可逃逸的片段，也没有第二条命令。
//
// 裸调 powershell 本身是被 deny 的（win-deny-host），用户拿不到解释器。
// PowerShellExe 返回要用的 PowerShell 可执行文件（Windows 才有意义）。
//
// 为什么优先 pwsh：每条命令都要起一次进程，而进程启动的钱每次都得付——
// 实测（同一台机器，`-NoProfile -NonInteractive -Command 1`）：
//
//	powershell.exe（5.1）  ~1.6s   .NET Framework 冷启动，与命令内容无关
//	powershell.exe -MTA    ~1.4s
//	pwsh.exe（7）          ~0.25s
//	cmd.exe /c            ~0.04s
//
// 也就是说 `ls` 那两秒几乎全是 PowerShell 5.1 的启动，不是策略、不是 RPC。
// 换 pwsh 能把它压到 0.3s；机器上没装 7 就回退 5.1，功能不变、只是慢。
func PowerShellExe() string {
	psOnce.Do(func() {
		if p, err := exec.LookPath("pwsh"); err == nil {
			psExe = p
			return
		}
		psExe = "powershell.exe"
	})
	return psExe
}

var (
	psOnce sync.Once
	psExe  string
)

func buildArgv(argv []string) []string {
	if runtime.GOOS != "windows" {
		return argv
	}
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		// ParseLine 只把引号当分隔符，这里按需要补回去，保证含空格的路径不断开
		if strings.ContainsAny(a, " \t") {
			parts = append(parts, `"`+a+`"`)
			continue
		}
		parts = append(parts, a)
	}
	return []string{PowerShellExe(), "-NoProfile", "-NonInteractive", "-Command", strings.Join(parts, " ")}
}

// Run 执行一条命令。
func (e *Executor) Run(ctx context.Context, req ExecReq) ExecResp {
	start := time.Now()
	resp := ExecResp{ExitCode: -1}
	defer func() { resp.CostMS = time.Since(start).Milliseconds() }()

	if len(req.Argv) == 0 {
		resp.Error = "empty argv"
		return resp
	}
	cwd, err := e.resolveCwd(req.Cwd)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Windows 上命令要包一层 PowerShell，见 buildArgv 的说明
	argv := buildArgv(req.Argv)
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	if cwd != "" {
		cmd.Dir = cwd
	}
	buf := limitedWriter{max: e.maxOutput}
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	// 超时/取消要能杀掉整棵进程树，否则 shell 拉起的子进程会变孤儿
	setKillTree(cmd)
	cmd.WaitDelay = 3 * time.Second

	err = cmd.Run()
	switch {
	case err == nil:
		resp.ExitCode = 0
	case runCtx.Err() == context.DeadlineExceeded:
		resp.ExitCode = -1
		resp.Error = fmt.Sprintf("timeout after %s", timeout)
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			resp.ExitCode = ee.ExitCode()
		} else {
			resp.ExitCode = -1
		}
		resp.Error = err.Error()
	}

	data := buf.buf.Bytes()
	resp.Bytes = len(data)
	resp.Truncated = buf.truncated
	if len(data) > previewBytes {
		resp.Output = string(data[:previewBytes])
	} else {
		resp.Output = string(data)
	}
	resp.OutputID = e.put(data)
	return resp
}

// Read 读输出分片。
func (e *Executor) Read(req OutputReq) (OutputResp, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.outputs[req.OutputID]
	if !ok {
		return OutputResp{}, errors.New("output not found or expired")
	}
	offset := max(0, min(req.Offset, len(b.data)))
	length := req.Length
	if length <= 0 {
		length = chunkMaxBytes
	}
	length = min(length, chunkMaxBytes)
	end := min(offset+length, len(b.data))
	return OutputResp{
		Offset: offset,
		Data:   string(b.data[offset:end]),
		Total:  len(b.data),
		EOF:    end >= len(b.data),
	}, nil
}

// Resolve 解析 cd 的目标目录。
//
// cd 是 shell 内置，exec 里既没有 cd.exe 也不该为它开一个 shell——所以
// 这里**只做路径计算与校验，不执行任何进程**：越界由 AllowRoot 挡住，
// 存在性与是否目录用 Stat 确认，结果回给 gate 存进会话。
func (e *Executor) Resolve(req ResolveReq) ResolveResp {
	target := strings.TrimSpace(req.Path)
	if target == "" {
		target = strings.TrimSpace(req.Base)
	}
	if target == "" {
		target = e.allowRoot
	}
	if target == "" {
		wd, err := os.Getwd()
		if err != nil {
			return ResolveResp{Error: err.Error()}
		}
		return ResolveResp{Cwd: wd}
	}
	if !filepath.IsAbs(target) && strings.TrimSpace(req.Base) != "" {
		target = filepath.Join(strings.TrimSpace(req.Base), target)
	}
	abs, err := e.resolveCwd(target) // 内部做 Abs + AllowRoot 校验
	if err != nil {
		return ResolveResp{Error: "cd: " + err.Error()}
	}
	st, err := os.Stat(abs)
	if err != nil {
		return ResolveResp{Error: "cd: " + err.Error()}
	}
	if !st.IsDir() {
		return ResolveResp{Error: "cd: not a directory: " + abs}
	}
	return ResolveResp{Cwd: abs}
}

// resolveCwd 把 cwd 限制在 AllowRoot 之内（防 cd 越界到系统目录）。
func (e *Executor) resolveCwd(cwd string) (string, error) {
	if cwd == "" {
		return "", nil
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		return "", err
	}
	if e.allowRoot == "" {
		return abs, nil
	}
	root, err := filepath.Abs(e.allowRoot)
	if err != nil {
		return "", err
	}
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("cwd %s is outside allowed root %s", abs, root)
	}
	return abs, nil
}

// put 存一份输出并返回 id；超出容量淘汰最旧。
func (e *Executor) put(data []byte) string {
	id := fmt.Sprintf("o%d-%d", time.Now().UnixNano(), atomic.AddUint64(&e.seq, 1))
	e.mu.Lock()
	defer e.mu.Unlock()
	e.outputs[id] = &blob{data: data, at: time.Now()}
	e.order = append(e.order, id)
	for len(e.order) > keepOutputs {
		oldest := e.order[0]
		e.order = e.order[1:]
		delete(e.outputs, oldest)
	}
	return id
}

// Service agent 侧注册的 RPC 服务（服务名 "ops"）。
type Service struct {
	ex *Executor
}

// NewService 包装执行器成 RPC 服务。
func NewService(ex *Executor) *Service { return &Service{ex: ex} }

// Exec RPC 方法：执行一条命令。
func (s *Service) Exec(ctx context.Context, raw []byte) ([]byte, error) {
	var req ExecReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("bad exec request: %w", err)
	}
	resp := s.ex.Run(ctx, req)
	return json.Marshal(resp)
}

// Resolve RPC 方法：解析 cd 目标（不执行任何命令）。
func (s *Service) Resolve(ctx context.Context, raw []byte) ([]byte, error) {
	var req ResolveReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("bad resolve request: %w", err)
	}
	return json.Marshal(s.ex.Resolve(req))
}

// Output RPC 方法：取输出分片。
func (s *Service) Output(ctx context.Context, raw []byte) ([]byte, error) {
	var req OutputReq
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("bad output request: %w", err)
	}
	resp, err := s.ex.Read(req)
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

// limitedWriter 带上限的输出缓冲，超出即丢弃并在 truncated 上留标记。
type limitedWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	if room <= 0 {
		w.truncated = true
		return len(p), nil // 假装写成功：别让子进程收到 EPIPE 而改变行为
	}
	if len(p) > room {
		w.truncated = true
		p = p[:room]
	}
	return w.buf.Write(p)
}
