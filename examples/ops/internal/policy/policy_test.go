package policy

import "testing"

// check 用指定档位+平台的规则集判一条命令。
//
// 注意：**用户输入一律走 Linux 规则集**（统一入口），platform 传 PlatformWindows
// 得到的是"翻译产物白名单"，只用来复核 Translate 的输出。
func check(t *testing.T, level, platform, line string) Verdict {
	t.Helper()
	e, err := New(RulesFor(level, platform))
	if err != nil {
		t.Fatalf("compile rules for %s/%s: %v", level, platform, err)
	}
	argv, err := ParseLine(line)
	if err != nil {
		return Verdict{Decision: Deny, RuleID: "parse", Reason: err.Error()}
	}
	return e.Check(argv)
}

// TestLinuxRules 用户输入走 Linux 规则集：这是唯一入口。
func TestLinuxRules(t *testing.T) {
	cases := []struct {
		line string
		want Decision
		why  string
	}{
		{"ls", Allow, "列目录"},
		{"ls -l /var/log", Allow, "带参数也要过"},
		{"cat /var/log/app.log", Allow, "读日志"},
		{"cat C:\\var\\log\\app.log", Allow, "Windows 上只能敲盘符路径，规则要吃得下"},
		{"grep -n error /var/log/app.log", Allow, "搜文本"},
		{"head -n 20 app.log", Allow, "头 20 行"},
		{"tail -n 20 app.log", Allow, "尾 20 行"},
		{"tail -f app.log", Deny, "长驻跟踪不支持（参数级 deny）"},
		{"find /data -name *.log", Allow, "只读查找"},
		{"find /data -delete", Deny, "find 的写类参数"},
		{"find /data -exec rm", Deny, "同上"},
		{"ps aux", Allow, "看进程"},
		{"systemctl status nginx", Allow, "看服务"},
		{"systemctl restart nginx", Deny, "view 档不能起停"},
		{"rm -rf /data/tmp/x", Deny, "view 档不能删"},
		{"curl http://x", Deny, "下载类"},
		{"bash -c ls", Deny, "解释器"},
		{"top", Deny, "需要终端"},
		{"vi /etc/passwd", Deny, "交互式编辑"},
		{"less app.log", Deny, "分页需要终端"},
		{"chmod 777 x", Deny, "权限变更"},
		{"shutdown -h now", Deny, "关机"},
		{"dd if=/dev/zero of=/dev/sda", Deny, "裸设备写"},
		{"nc -l 4444", Deny, "反弹 shell 常用"},
		{"docker ps", Allow, "容器只读"},
		{"Get-ChildItem", Deny, "统一入口：不允许直接敲 Windows 命令"},
		{"Remove-Item C:\\x", Deny, "同上，且是写操作"},
	}
	for _, c := range cases {
		if got := check(t, LevelView, PlatformLinux, c.line); got.Decision != c.want {
			t.Errorf("%q (%s): got %s (%s), want %s", c.line, c.why, got.Decision, got.RuleID, c.want)
		}
	}
}

// TestLevels 档位分层：ops 能起停与杀进程，admin 才能受限写。
func TestLevels(t *testing.T) {
	if got := check(t, LevelOps, PlatformLinux, "systemctl restart nginx"); got.Decision != Allow {
		t.Errorf("ops restart: got %s (%s), want allow", got.Decision, got.RuleID)
	}
	if got := check(t, LevelOps, PlatformLinux, "kill 123"); got.Decision != Allow {
		t.Errorf("ops kill: got %s, want allow", got.Decision)
	}
	if got := check(t, LevelOps, PlatformLinux, "rm -rf /data/tmp/x"); got.Decision != Deny {
		t.Errorf("ops rm: got %s, want deny", got.Decision)
	}
	if got := check(t, LevelAdmin, PlatformLinux, "rm -rf /data/tmp/x"); got.Decision != Allow {
		t.Errorf("admin rm /data/tmp: got %s (%s), want allow", got.Decision, got.RuleID)
	}
	if got := check(t, LevelAdmin, PlatformLinux, "rm -rf /etc/passwd"); got.Decision != Deny {
		t.Errorf("admin rm /etc/passwd must stay denied, got %s", got.Decision)
	}
}

// TestPathSyntaxBothPlatforms 入口统一成 Linux 命令，但 Windows 上只能敲盘符路径——
// 同一条规则必须同时认这两种写法。
func TestPathSyntaxBothPlatforms(t *testing.T) {
	for _, p := range []string{"/data/tmp/a.log", `C:\data\tmp\a.log`} {
		if got := check(t, LevelAdmin, PlatformLinux, "rm -rf "+p); got.Decision != Allow {
			t.Errorf("admin rm %s: got %s (%s), want allow", p, got.Decision, got.RuleID)
		}
		if got := check(t, LevelAdmin, PlatformLinux, "cp a.txt "+p); got.Decision != Allow {
			t.Errorf("admin cp → %s: got %s, want allow", p, got.Decision)
		}
	}
	if got := check(t, LevelAdmin, PlatformLinux, `rm -rf D:\Windows\x`); got.Decision != Deny {
		t.Errorf("admin rm 出 data 目录 must stay denied, got %s", got.Decision)
	}
}

// TestBuiltin cd/pwd/help 是会话内置的，不进子进程。
func TestBuiltin(t *testing.T) {
	for _, line := range []string{"pwd", "cd", "cd internal", "cd ..", `cd C:\var\log`, "help"} {
		if !IsBuiltin(mustParse(t, line)) {
			t.Errorf("IsBuiltin(%q) = false, want true", line)
		}
		if got := check(t, LevelView, PlatformLinux, line); got.Decision != Allow {
			t.Errorf("%q: got %s (%s), want allow", line, got.Decision, got.RuleID)
		}
	}
	if IsBuiltin(mustParse(t, "ls")) {
		t.Error("IsBuiltin(ls) = true, want false")
	}
}

func mustParse(t *testing.T, line string) []string {
	t.Helper()
	argv, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine(%q): %v", line, err)
	}
	return argv
}

// TestWindowsReview Windows 规则集只复核翻译产物：模板里出现白名单外的
// 命令（哪怕是翻译表写错）必须拦下。
func TestWindowsReview(t *testing.T) {
	e, err := New(RulesFor(LevelView, PlatformWindows))
	if err != nil {
		t.Fatalf("compile windows rules: %v", err)
	}
	ok := [][]string{
		{"Get-ChildItem", "-Path", "."},
		{"Get-ChildItem", "-Path", ".", "|", "Format-Table", "-AutoSize", "Mode,LastWriteTime,Length,Name"},
		{"Get-Content", "-Path", "a.log", "-TotalCount", "20"},
		{"Select-String", "-Pattern", "err", "-Path", "a.log"},
		{"Get-Process"},
		{"Get-CimInstance", "Win32_OperatingSystem", "|", "Select-Object", "Caption"},
		{"ping", "-n", "4", "a.com"},
		{"whoami", "/groups"},
	}
	for _, argv := range ok {
		if err := CheckPipeline(e, argv); err != nil {
			t.Errorf("CheckPipeline(%v): %v, want nil", argv, err)
		}
	}
	bad := [][]string{
		{"Remove-Item", "-Path", "x"},             // view 档：写类 cmdlet 不在白名单
		{"Invoke-WebRequest", "-Uri", "http://x"}, // 下载
		{"powershell", "-c", "ls"},                // 解释器
		{"Get-ChildItem", "|"},                    // 空管道段
		{"cmd", "/c", "dir"},
	}
	for _, argv := range bad {
		if err := CheckPipeline(e, argv); err == nil {
			t.Errorf("CheckPipeline(%v) = nil, want error", argv)
		}
	}
}

// TestWindowsReviewAdmin admin 档的复核里才有写类 cmdlet。
func TestWindowsReviewAdmin(t *testing.T) {
	e, err := New(RulesFor(LevelAdmin, PlatformWindows))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckPipeline(e, []string{"Remove-Item", "-Path", `C:\data\tmp\x`, "-Recurse"}); err != nil {
		t.Errorf("admin Remove-Item: %v, want nil", err)
	}
	if err := CheckPipeline(e, []string{"Stop-Process", "-Id", "123"}); err != nil {
		t.Errorf("admin Stop-Process: %v, want nil", err)
	}
}

// TestAnchorAndExt 两个容易漏的缝：交替正则的锚点、可执行后缀。
func TestAnchorAndExt(t *testing.T) {
	// `at` 只是计划任务命令，不能因为名字里含 "at" 就拒（曾在 Windows 上误伤 Get-Date）
	e, err := New(RulesFor(LevelView, PlatformWindows))
	if err != nil {
		t.Fatal(err)
	}
	if v := e.Check([]string{"Get-Date"}); v.Decision != Allow {
		t.Errorf("Get-Date: got %s (%s), want allow", v.Decision, v.RuleID)
	}
	// Linux 侧同理：含 "su" 子串的命令不该被 deny-user 误伤
	if got := check(t, LevelView, PlatformLinux, "sum --version"); got.RuleID != "default" {
		t.Errorf("sum: matched %s, want default-deny（不是 su 规则）", got.RuleID)
	}
	// .exe 后缀必须归一化，否则 deny 规则形同虚设
	for _, line := range []string{"sc.exe query", "net.exe user", "cmd.exe /c dir", "powershell.exe -c ls"} {
		if got := check(t, LevelView, PlatformLinux, line); got.Decision != Deny {
			t.Errorf("%q: got %s, want deny", line, got.Decision)
		}
	}
}

// TestParseLine 元字符是硬边界——Windows 走 PowerShell 包装后，它更是唯一的逃逸防线。
func TestParseLine(t *testing.T) {
	for _, bad := range []string{"a; b", "a | b", "a & b", "a $(b)", "a `b`", "a > b", "a < b"} {
		if _, err := ParseLine(bad); err == nil {
			t.Errorf("ParseLine(%q) should reject", bad)
		}
	}
	argv, err := ParseLine(`cat "C:\Program Files\a.log"`)
	if err != nil {
		t.Fatalf("quoted path: %v", err)
	}
	if len(argv) != 2 || argv[1] != `C:\Program Files\a.log` {
		t.Errorf("quoted path split: %#v", argv)
	}
}
