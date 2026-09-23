package main

// 账号表与授权表的加载。
//
// 两个文件都是可选的：不存在就用内置默认（demo / demo，view 档，全机器），
// 并在日志里警告。默认档位是最保守的，但**默认口令必须换掉**。
//
// 真实环境把 loadUsers 换成 LDAP / OAuth / 内部账号系统即可，
// 授权表（用户 × 机器 × 档位）通常来自你们自己的权限系统。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/w6xian/sloth-proxy/examples/ops/internal/authn"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/authz"
	"github.com/w6xian/sloth-proxy/examples/ops/internal/policy"
)

// userConf 一个账号。
//
// pass 是 bcrypt 哈希（推荐）；pass_plain 是明文，只为**初次上手**省事，
// 正式部署请删掉它、只留 pass。
type userConf struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Pass      string `json:"pass"`
	PassPlain string `json:"pass_plain"`
}

// loadUsers 加载账号表。path 为空或文件不存在时用内置默认账号。
func loadUsers(path string) (*authn.Static, error) {
	st := authn.NewStatic()
	if path == "" {
		return st, defaultUsers(st)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read users %s: %w", path, err)
		}
		return st, defaultUsers(st)
	}
	var list []userConf
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parse users %s: %w", path, err)
	}
	for _, u := range list {
		if u.Name == "" {
			continue
		}
		user := authn.User{Name: u.Name, Label: u.Label}
		switch {
		case u.Pass != "":
			if err := st.AddHash(user, u.Pass); err != nil {
				return nil, fmt.Errorf("user %s: %w", u.Name, err)
			}
		case u.PassPlain != "":
			if err := st.Add(user, u.PassPlain); err != nil {
				return nil, fmt.Errorf("user %s: %w", u.Name, err)
			}
		default:
			return nil, fmt.Errorf("user %s: need pass or pass_plain", u.Name)
		}
	}
	if len(list) == 0 {
		return st, defaultUsers(st)
	}
	return st, nil
}

// defaultUsers 内置默认账号：demo / demo。仅为"能立刻跑起来"，务必替换。
func defaultUsers(st *authn.Static) error {
	if err := st.Add(authn.User{Name: "demo", Label: "演示账号"}, "demo"); err != nil {
		return err
	}
	fmt.Println("警告：未配置账号表，使用内置账号 demo/demo —— 正式部署请在 users.json 里换掉")
	return nil
}

// loadGrants 加载授权表（用户 × 机器 × 档位）。文件不存在时用默认授权。
func loadGrants(path string) (*authz.Store, error) {
	if path == "" {
		return authz.New(defaultGrants()), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read grants %s: %w", path, err)
		}
		return authz.New(defaultGrants()), nil
	}
	var list []authz.Grant
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parse grants %s: %w", path, err)
	}
	if len(list) == 0 {
		list = defaultGrants()
	}
	return authz.New(list), nil
}

// defaultGrants 默认授权：demo 在全部机器上只有 view 档（只读）。
func defaultGrants() []authz.Grant {
	return []authz.Grant{{User: "demo", Machine: "*", Level: policy.LevelView}}
}
