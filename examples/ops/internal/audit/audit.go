// Package audit 审计记录。
//
// 审计是红线，因此两条硬要求：
//  1. **请求与拒绝都要记**：谁在试探边界，是最有价值的日志；
//  2. 记录先落盘再返回：进程崩了也不能丢最后一条。
//
// 这里用 append-only 的 JSONL 文件（每行一条），配内存 ring 供页面查询。
// 生产建议换成独立的日志服务/数据库，但"先落盘"这条不要改。
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry 一条审计记录。
type Entry struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	User     string    `json:"user"`
	Level    string    `json:"level"`
	Machine  string    `json:"machine"`
	Line     string    `json:"line"`
	Argv     []string  `json:"argv"`
	Decision string    `json:"decision"`
	RuleID   string    `json:"rule_id"`
	Reason   string    `json:"reason,omitempty"`
	ExitCode int       `json:"exit_code"`
	Bytes    int       `json:"bytes"`
	CostMS   int64     `json:"cost_ms"`
	OutputID string    `json:"output_id,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// Recorder 审计记录器：文件落盘 + 内存 ring。
type Recorder struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	ring []Entry
	keep int
}

// New 打开（或创建）审计文件。keep 是内存保留条数，仅影响页面查询上限。
func New(path string, keep int) (*Recorder, error) {
	if keep <= 0 {
		keep = 1000
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{f: f, enc: json.NewEncoder(f), ring: make([]Entry, 0, keep), keep: keep}, nil
}

// Record 写一条审计：先落盘再进内存 ring。
func (r *Recorder) Record(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.enc.Encode(e); err != nil {
		return err
	}
	r.ring = append(r.ring, e)
	if len(r.ring) > r.keep {
		r.ring = r.ring[len(r.ring)-r.keep:]
	}
	return nil
}

// Recent 最近 n 条（倒序，最新的在前）。
func (r *Recorder) Recent(n int) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.ring) {
		n = len(r.ring)
	}
	out := make([]Entry, 0, n)
	for i := len(r.ring) - 1; i >= len(r.ring)-n; i-- {
		out = append(out, r.ring[i])
	}
	return out
}

// Close 关闭审计文件。
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
