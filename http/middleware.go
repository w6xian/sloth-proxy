package http

import (
	"net/http"
)

// Auth 按请求做鉴权，不通过就 401。
//
// 网关本身不做任何身份判断——"谁能访问内网"是使用方的策略，
// 所以放在这里包一层，而不是进转发主流程。
//
// check 返回 true 表示放行；传 nil 表示全部放行（方便按环境开关）。
func Auth(next http.Handler, check func(*http.Request) bool) http.Handler {
	if next == nil {
		panic("http: nil handler")
	}
	if check == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !check(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Methods 限制请求方法。
//
// 网关只能转发无 body 的请求（入参上限 65535 只够放请求头），
// 默认放行 GET / HEAD，其余回 405。
func Methods(next http.Handler, allowed ...string) http.Handler {
	if next == nil {
		panic("http: nil handler")
	}
	if len(allowed) == 0 {
		allowed = []string{http.MethodGet, http.MethodHead}
	}
	set := make(map[string]struct{}, len(allowed))
	for _, m := range allowed {
		set[m] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := set[r.Method]; !ok {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}
