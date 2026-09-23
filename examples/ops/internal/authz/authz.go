// Package authz 授权：用户 × 机器 × 档位。
//
// 授权只回答"这个人在这台机器上是什么档位"，**不回答能不能执行某条命令**——
// 后者由 policy 按档位对应的规则集判定。两者分开，档位和命令规则可以各自演进。
package authz

import (
	"strings"
	"sync"

	"github.com/w6xian/sloth-proxy/examples/ops/internal/policy"
)

// 档位：沿用 policy 的定义，避免两处漂移。
const (
	LevelView  = policy.LevelView
	LevelOps   = policy.LevelOps
	LevelAdmin = policy.LevelAdmin
)

// Grant 一条授权。Machine 支持通配：`*` 全部，`web*` 前缀。
type Grant struct {
	User    string `json:"user"`
	Machine string `json:"machine"`
	Level   string `json:"level"`
}

// Store 授权表。
type Store struct {
	mu     sync.RWMutex
	grants []Grant
}

// New 建立授权表。
func New(grants []Grant) *Store {
	cp := make([]Grant, 0, len(grants))
	for _, g := range grants {
		g.User = strings.TrimSpace(g.User)
		g.Machine = strings.TrimSpace(g.Machine)
		g.Level = strings.TrimSpace(g.Level)
		if g.User == "" || g.Machine == "" || g.Level == "" {
			continue
		}
		cp = append(cp, g)
	}
	return &Store{grants: cp}
}

// Level 取用户在某台机器上的档位；没授权返回 ok=false。
//
// 多条命中取**最高**档位（admin > ops > view）。
func (s *Store) Level(user, machine string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	best, ok := "", false
	for _, g := range s.grants {
		if g.User != user && g.User != "*" {
			continue
		}
		if !matchMachine(g.Machine, machine) {
			continue
		}
		if !ok || rank(g.Level) > rank(best) {
			best, ok = g.Level, true
		}
	}
	return best, ok
}

// Filter 过滤出用户有权的机器（保持输入顺序）。
func (s *Store) Filter(user string, machines []string) []string {
	out := make([]string, 0, len(machines))
	for _, m := range machines {
		if _, ok := s.Level(user, m); ok {
			out = append(out, m)
		}
	}
	return out
}

// GrantsOf 用户的所有授权（页面展示用）。
func (s *Store) GrantsOf(user string) []Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		if g.User == user || g.User == "*" {
			out = append(out, g)
		}
	}
	return out
}

// matchMachine 机器名匹配：* 全通，web* 前缀，其余精确。
func matchMachine(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

// rank 档位高低。未知档位按最低处理（宁可少给权限）。
func rank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case LevelAdmin:
		return 3
	case LevelOps:
		return 2
	case LevelView:
		return 1
	}
	return 0
}
