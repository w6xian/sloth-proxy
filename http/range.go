package http

import (
	"errors"
	"strconv"
	"strings"
)

// rangeSpec 解析 RFC 7233 的 Range 子集，返回要读的闭区间 [start, end]。
//
// 返回 errNoRange：没有 Range 或单位不是 bytes → 按全量处理（RFC 要求忽略，
// 不是报错）。返回 errUnsatisfiable：区间越界 → 416。语法不认识的一律忽略，
// 只对"认识但满足不了"报错。
func rangeSpec(h string, size int64) (start, end int64, err error) {
	if size <= 0 {
		return 0, 0, errUnsatisfiable
	}
	if h == "" {
		return 0, size - 1, errNoRange
	}
	spec := strings.TrimSpace(h)
	if !strings.HasPrefix(spec, "bytes=") {
		return 0, size - 1, errNoRange
	}
	spec = strings.TrimSpace(strings.TrimPrefix(spec, "bytes="))
	// 多区间只取第一个：浏览器基本不发，真发了也按单区间回（HTTP 允许）
	if i := strings.IndexByte(spec, ','); i >= 0 {
		spec = spec[:i]
	}
	if spec == "" {
		return 0, size - 1, errNoRange
	}
	if strings.HasPrefix(spec, "-") {
		// 后缀形式 bytes=-N：最后 N 字节
		n, err := strconv.ParseInt(spec[1:], 10, 64)
		if err != nil || n <= 0 {
			return 0, size - 1, errNoRange
		}
		start = max(0, size-n)
		end = size - 1
	} else {
		dash := strings.IndexByte(spec, '-')
		if dash < 0 {
			return 0, size - 1, errNoRange
		}
		s, err := strconv.ParseInt(spec[:dash], 10, 64)
		if err != nil {
			return 0, size - 1, errNoRange
		}
		start = s
		if dash == len(spec)-1 {
			end = size - 1 // bytes=100-  → 读到结尾
		} else {
			e, err := strconv.ParseInt(spec[dash+1:], 10, 64)
			if err != nil {
				return 0, size - 1, errNoRange
			}
			end = e
		}
		if end >= size {
			end = size - 1 // end 越界截断，不是错误
		}
	}
	if start < 0 || start > end || start >= size {
		return 0, 0, errUnsatisfiable
	}
	return start, end, nil
}

// rangeSpec 的两种"没拿到区间"：前者按全量处理，后者回 416。
var (
	errNoRange       = errors.New("no range")
	errUnsatisfiable = errors.New("unsatisfiable range")
)
