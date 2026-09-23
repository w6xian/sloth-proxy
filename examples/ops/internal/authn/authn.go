// Package authn 登录与会话。
//
// 这是**接入点**，不是最终实现：真实环境把 Authenticator 换成 LDAP / OAuth /
// 内部账号系统即可，gate 侧其余代码不用改。
//
// 两条硬要求：
//  1. 口令只存哈希（bcrypt），明文不落盘、不打日志；
//  2. 会话 token 用 crypto/rand，不用自增 ID / 时间戳（可被猜）。
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ErrBadCredential 用户名或口令不对。
//
// 对外只回这一个错误：不要区分"用户不存在"和"口令错"，避免被用来枚举账号。
var ErrBadCredential = errors.New("用户名或口令错误")

// User 登录用户。Name 进审计（主键），Label 只用于展示。
type User struct {
	Name  string `json:"name"`
	Label string `json:"label"`
}

// Authenticator 登录校验接口。
type Authenticator interface {
	Verify(user, pass string) (*User, error)
}

// Static 内置账号表。
//
// 适合小团队/起步阶段；人多了换 LDAP / OAuth 实现同一个接口即可。
type Static struct {
	mu    sync.RWMutex
	users map[string]staticUser
}

type staticUser struct {
	User
	hash []byte
}

// NewStatic 创建空账号表。
func NewStatic() *Static {
	return &Static{users: map[string]staticUser{}}
}

// Add 用明文口令加用户（内部转 bcrypt 哈希）。
func (s *Static) Add(u User, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.AddHash(u, string(hash))
}

// AddHash 用已有的 bcrypt 哈希加用户。
func (s *Static) AddHash(u User, hash string) error {
	if u.Name == "" {
		return errors.New("empty user name")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("probe")); err != nil &&
		!errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return errors.New("bad bcrypt hash: " + err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Name] = staticUser{User: u, hash: []byte(hash)}
	return nil
}

// Verify 校验口令。
func (s *Static) Verify(user, pass string) (*User, error) {
	s.mu.RLock()
	u, ok := s.users[user]
	s.mu.RUnlock()
	// 用户不存在也要走一次哈希比对，避免用响应时间判断账号是否存在
	dummy := []byte("$2a$10$0000000000000000000000000000000000000000000000000000")
	h := u.hash
	if !ok {
		h = dummy
	}
	if err := bcrypt.CompareHashAndPassword(h, []byte(pass)); err != nil || !ok {
		return nil, ErrBadCredential
	}
	out := u.User
	return &out, nil
}

// SessionStore 会话表：token → 用户。
//
// 进程内实现，重启即失效；要保持登录就换成 Redis / DB 实现同样的三个方法。
type SessionStore struct {
	mu   sync.Mutex
	m    map[string]session
	ttl  time.Duration
	last time.Time
}

type session struct {
	user   User
	expire time.Time
	// cwd 机器名 → 当前目录。cd 是 shell 内置（exec 里没有 cd.exe），
	// 只能把"我在哪"记在会话里；按机器分开，切换机器不会串目录。
	cwd map[string]string
}

// NewSessionStore 创建会话表。ttl 过后会话失效。
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return &SessionStore{m: map[string]session{}, ttl: ttl}
}

// New 建一个会话，返回 token。
func (s *SessionStore) New(u User) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺手清理过期会话：不额外起定时器，写的时候扫一遍就够
	if now := time.Now(); now.Sub(s.last) > time.Minute {
		for k, v := range s.m {
			if now.After(v.expire) {
				delete(s.m, k)
			}
		}
		s.last = now
	}
	s.m[token] = session{user: u, expire: time.Now().Add(s.ttl)}
	return token, nil
}

// Get 取会话用户。token 不对或已过期返回 false。
func (s *SessionStore) Get(token string) (User, bool) {
	if token == "" {
		return User{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[token]
	if !ok || time.Now().After(v.expire) {
		if ok {
			delete(s.m, token)
		}
		return User{}, false
	}
	return v.user, true
}

// Cwd 取会话在某台机器上的当前目录；没 cd 过返回空。
func (s *SessionStore) Cwd(token, machine string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[token]
	if !ok || time.Now().After(v.expire) {
		return ""
	}
	return v.cwd[machine]
}

// SetCwd 更新会话在某台机器上的当前目录。
func (s *SessionStore) SetCwd(token, machine, cwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[token]
	if !ok || time.Now().After(v.expire) {
		return
	}
	if cwd == "" {
		delete(v.cwd, machine)
		return
	}
	if v.cwd == nil {
		v.cwd = map[string]string{}
		s.m[token] = v // map 本身是引用，但 v.cwd 从 nil 变非 nil 要写回
	}
	v.cwd[machine] = cwd
}

// Del 删除会话（登出）。
func (s *SessionStore) Del(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
}

// ConstantTimeEqual 常量时间比较（防时序侧信道）。
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
