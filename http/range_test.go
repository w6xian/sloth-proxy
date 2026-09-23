package http

import (
	"errors"
	"testing"
)

func TestRangeSpec(t *testing.T) {
	const size = 1000

	cases := []struct {
		name      string
		header    string
		wantStart int64
		wantEnd   int64
		wantErr   error
	}{
		{"无 Range 按全量", "", 0, 999, errNoRange},
		{"单位不是 bytes 也按全量", "items=0-9", 0, 999, errNoRange},
		{"空 bytes= 按全量", "bytes=", 0, 999, errNoRange},
		{"语法不认识按全量", "bytes=abc", 0, 999, errNoRange},
		{"闭区间", "bytes=0-99", 0, 99, nil},
		{"开区间读到结尾", "bytes=100-", 100, 999, nil},
		{"后缀形式", "bytes=-100", 900, 999, nil},
		{"后缀超过全长", "bytes=-5000", 0, 999, nil},
		{"end 越界截断", "bytes=900-5000", 900, 999, nil},
		{"多区间只取第一个", "bytes=0-9,20-29", 0, 9, nil},
		{"start 越界 416", "bytes=1000-", 0, 0, errUnsatisfiable},
		{"start 大于 end 416", "bytes=500-100", 0, 0, errUnsatisfiable},
		{"size 为 0 一律 416", "bytes=0-0", 0, 0, errUnsatisfiable},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sz := int64(size)
			if c.name == "size 为 0 一律 416" {
				sz = 0
			}
			start, end, err := rangeSpec(c.header, sz)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if c.wantErr != nil {
				return
			}
			if start != c.wantStart || end != c.wantEnd {
				t.Fatalf("got [%d,%d], want [%d,%d]", start, end, c.wantStart, c.wantEnd)
			}
		})
	}
}
