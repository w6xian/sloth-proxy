package policy

// 统一命令层：Linux 是**唯一入口**，Windows 只是执行端。
//
// 为什么不做"两套白名单"（Windows 让人敲 Get-*、Linux 让人敲 ls）：
//  1. 人会串台，规则集会有两套真相，改一处忘一处；
//  2. 更实际的：问"这台机器上允许什么"时得回答两遍，审计里同一次操作
//     在不同机器上是两个名字，排查时没法对齐。
//
// 所以链路固定为：
//
//	用户输入（Linux 命令）→ Linux 规则集判定 → 翻译层 → Windows 规则集复核 → 下发
//
// 翻译是**确定性模板**：用户输入只作为路径/pattern 等"值"填进去，而值已经
// 被 Linux 规则集的参数正则约束过（且 ParseLine 拒掉了 ; | & $ ` 等元字符），
// 所以模板里的管道不会被用户用来接第二条命令。
//
// 复核那一步是给翻译表买的保险：万一哪条模板写错、吐出 Remove-Item，
// Windows 规则集会把它拦下来。

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// ErrNoWindowsEquivalent 这条 Linux 命令在 Windows 上没有对应实现。
//
// 不是"不允许"，是"做不到"——与其让 PowerShell 报一堆红字，不如在这层说清楚
// 并给出替代命令。
type ErrNoWindowsEquivalent struct {
	Cmd string
	Alt string
}

func (e *ErrNoWindowsEquivalent) Error() string {
	if e.Alt == "" {
		return e.Cmd + ": 该命令在 Windows 上没有对应实现"
	}
	return e.Cmd + ": 该命令在 Windows 上没有对应实现；可改用 " + e.Alt
}

// Mapping 一条 Linux 命令在 Windows 上的落点，用于向用户展示对照表。
type Mapping struct {
	Linux   string `json:"linux"`
	Windows string `json:"windows"` // 为空表示无对应实现
	Note    string `json:"note,omitempty"`
}

type xlate struct {
	cmd string                                // Linux 命令名（精确匹配 basename）
	fn  func(argv []string) ([]string, error) // 生成 Windows argv
	alt string                                // fn == nil 时的替代建议
}

// xlateTable 对照表。顺序无关（内部按命令名索引），但按文章分类排列便于补齐。
var xlateTable = []xlate{
	// ── 文件和目录操作 ──
	{cmd: "ls", fn: xlateLs},
	{cmd: "cd", fn: builtinNoop},  // 会话内置，不下发
	{cmd: "pwd", fn: builtinNoop}, // 同上
	{cmd: "cp", fn: xlateCp},
	{cmd: "find", fn: xlateFind},
	{cmd: "mkdir", fn: xlateMkdir},
	{cmd: "mv", fn: xlateMv},
	{cmd: "rename", fn: xlateRename},
	{cmd: "rm", fn: xlateRm},
	{cmd: "rmdir", fn: xlateRm},
	{cmd: "touch", fn: xlateTouch},
	{cmd: "tree", fn: func(argv []string) ([]string, error) {
		p := firstPos(argv)
		if p == "" {
			return []string{"Get-ChildItem", "-Recurse"}, nil
		}
		return []string{"Get-ChildItem", "-Path", p, "-Recurse"}, nil
	}},
	{cmd: "basename", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Split-Path", "-Leaf")
	}},
	{cmd: "dirname", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Split-Path", "-Parent")
	}},
	{cmd: "md5sum", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Get-FileHash", "-Algorithm", "MD5", "-Path")
	}},
	{cmd: "chattr", alt: "attrib（扩展属性模型不同，不翻译）"},
	{cmd: "lsattr", alt: "attrib"},
	{cmd: "file", alt: "Get-Item（只能看类型名，看不出编码）"},

	// ── 查看文件及内容处理 ──
	{cmd: "cat", fn: xlateCat},
	{cmd: "head", fn: xlateHead},
	{cmd: "tail", fn: xlateTail},
	{cmd: "grep", fn: xlateGrep},
	{cmd: "egrep", fn: xlateGrep},
	{cmd: "sort", fn: func(argv []string) ([]string, error) {
		return pipeFile(argv, "Sort-Object")
	}},
	{cmd: "uniq", fn: func(argv []string) ([]string, error) {
		return pipeFile(argv, "Get-Unique")
	}},
	{cmd: "wc", fn: xlateWc},
	{cmd: "diff", fn: func(argv []string) ([]string, error) {
		_, pos := flagsPos(argv)
		if len(pos) < 2 {
			return nil, errors.New("diff: 需要两个文件")
		}
		return []string{"Compare-Object", "(Get-Content", pos[0] + ")", "(Get-Content", pos[1] + ")"}, nil
	}},
	{cmd: "tac", alt: "Get-Content（顺序相反，需自行处理）"},
	{cmd: "rev", alt: "无对应实现"},
	{cmd: "cut", alt: "Get-Content 后用 ForEach-Object 切分（不翻译：参数语义差异太大）"},
	{cmd: "split", alt: "无对应实现"},
	{cmd: "paste", alt: "无对应实现"},
	{cmd: "join", alt: "无对应实现"},
	{cmd: "tr", alt: "无对应实现（tr 靠重定向，这边没有）"},
	{cmd: "iconv", alt: "无对应实现"},
	{cmd: "dos2unix", alt: "Get-Content 后 -replace \"`r\"（不翻译）"},
	{cmd: "more", alt: "Get-Content / head / tail（分页需要终端，不支持）"},
	{cmd: "less", alt: "Get-Content / head / tail（分页需要终端，不支持）"},
	{cmd: "vi", alt: "不支持交互式编辑"},
	{cmd: "vim", alt: "不支持交互式编辑"},
	{cmd: "vimdiff", alt: "diff（Compare-Object）"},

	// ── 压缩解压：一律不翻（解压会覆盖文件，属于写操作） ──
	{cmd: "tar", alt: "无对应实现（解压覆盖风险，走审批过的任务）"},
	{cmd: "zip", alt: "Compress-Archive（写操作，当前档位不放开）"},
	{cmd: "unzip", alt: "Expand-Archive（写操作，当前档位不放开）"},
	{cmd: "gzip", alt: "Compress-Archive（写操作，当前档位不放开）"},

	// ── 信息显示 ──
	{cmd: "uname", fn: func(argv []string) ([]string, error) {
		return []string{"Get-CimInstance", "Win32_OperatingSystem", "|", "Select-Object", "Caption,Version,BuildNumber"}, nil
	}},
	{cmd: "hostname", fn: passthrough},
	{cmd: "uptime", fn: func(argv []string) ([]string, error) {
		return []string{"Get-CimInstance", "Win32_OperatingSystem", "|", "Select-Object", "LastBootUpTime"}, nil
	}},
	{cmd: "stat", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Get-Item", "-Path")
	}},
	{cmd: "du", fn: func(argv []string) ([]string, error) {
		p := firstPos(argv)
		if p == "" {
			p = "."
		}
		return []string{"Get-ChildItem", "-Path", p, "-Recurse", "-File", "|",
			"Measure-Object", "-Property", "Length", "-Sum"}, nil
	}},
	{cmd: "df", fn: func(argv []string) ([]string, error) {
		return []string{"Get-PSDrive", "-PSProvider", "FileSystem"}, nil
	}},
	{cmd: "free", fn: func(argv []string) ([]string, error) {
		return []string{"Get-CimInstance", "Win32_OperatingSystem", "|", "Select-Object",
			"TotalVisibleMemorySize,FreePhysicalMemory"}, nil
	}},
	{cmd: "date", fn: func(argv []string) ([]string, error) { return []string{"Get-Date"}, nil }},
	{cmd: "top", alt: "ps（Get-Process）——实时刷新需要终端"},
	{cmd: "dmesg", alt: "Get-EventLog -LogName System -Newest 50"},
	{cmd: "cal", alt: "无对应实现"},

	// ── 搜索文件 ──
	{cmd: "which", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Get-Command", "-Name")
	}},
	{cmd: "whereis", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Get-Command", "-Name")
	}},
	{cmd: "locate", alt: "Get-ChildItem -Recurse -Filter（没有索引库，会慢）"},

	// ── 用户与登录信息 ──
	{cmd: "whoami", fn: passthrough},
	{cmd: "id", fn: func(argv []string) ([]string, error) { return []string{"whoami", "/groups"}, nil }},
	{cmd: "who", fn: func(argv []string) ([]string, error) { return []string{"quser"}, nil }},
	{cmd: "w", alt: "quser"},
	{cmd: "last", alt: "Get-EventLog -LogName Security（登录审计，语义不同）"},
	{cmd: "lastlog", alt: "无对应实现"},
	{cmd: "users", alt: "quser"},
	{cmd: "finger", alt: "无对应实现"},

	// ── 基础网络 ──
	{cmd: "ping", fn: xlatePing},
	{cmd: "ifconfig", fn: func(argv []string) ([]string, error) {
		return []string{"Get-NetIPConfiguration"}, nil
	}},
	{cmd: "ip", fn: xlateIP},
	{cmd: "route", fn: func(argv []string) ([]string, error) { return []string{"Get-NetRoute"}, nil }},
	{cmd: "netstat", fn: func(argv []string) ([]string, error) {
		return []string{"Get-NetTCPConnection"}, nil
	}},
	{cmd: "ss", fn: func(argv []string) ([]string, error) {
		return []string{"Get-NetTCPConnection"}, nil
	}},
	{cmd: "ifup", alt: "无对应实现（改网卡属于变更操作）"},
	{cmd: "ifdown", alt: "无对应实现（改网卡属于变更操作）"},

	// ── 深入网络 ──
	{cmd: "nslookup", fn: passthrough},
	{cmd: "dig", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Resolve-DnsName", "-Name")
	}},
	{cmd: "host", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Resolve-DnsName", "-Name")
	}},
	{cmd: "traceroute", fn: func(argv []string) ([]string, error) {
		out := []string{"tracert"}
		_, pos := flagsPos(argv)
		return append(out, pos...), nil
	}},
	{cmd: "lsof", alt: "Get-NetTCPConnection / Get-Process（Windows 没有打开的 fd 视图）"},

	// ── 磁盘与文件系统：除 sync 外全是变更类，规则集已 deny，这里只给提示 ──
	{cmd: "sync", alt: "无对应实现"},
	{cmd: "mount", alt: "无对应实现（挂载禁止）"},
	{cmd: "umount", alt: "无对应实现（挂载禁止）"},
	{cmd: "fsck", alt: "无对应实现（磁盘修复禁止）"},
	{cmd: "e2fsck", alt: "无对应实现"},
	{cmd: "mkfs", alt: "无对应实现（格式化禁止）"},
	{cmd: "fdisk", alt: "无对应实现（分区禁止）"},
	{cmd: "parted", alt: "无对应实现（分区禁止）"},
	{cmd: "dd", alt: "无对应实现（裸设备写禁止）"},
	{cmd: "swapon", alt: "无对应实现"},
	{cmd: "swapoff", alt: "无对应实现"},
	{cmd: "mkswap", alt: "无对应实现"},
	{cmd: "dumpe2fs", alt: "无对应实现"},
	{cmd: "dump", alt: "无对应实现"},
	{cmd: "partprobe", alt: "无对应实现"},
	{cmd: "resize2fs", alt: "无对应实现"},

	// ── 权限：规则集 deny ──
	{cmd: "chmod", alt: "无对应实现（权限变更禁止）"},
	{cmd: "chown", alt: "无对应实现（属主变更禁止）"},
	{cmd: "chgrp", alt: "无对应实现（属组变更禁止）"},
	{cmd: "umask", alt: "无对应实现"},

	// ── 内置命令及其它 ──
	{cmd: "echo", fn: func(argv []string) ([]string, error) {
		return append([]string{"Write-Output"}, argv[1:]...), nil
	}},
	{cmd: "clear", fn: func(argv []string) ([]string, error) { return []string{"Clear-Host"}, nil }},
	{cmd: "printf", alt: "echo（Write-Output，不做格式化）"},
	{cmd: "history", alt: "上下键翻历史（浏览器里没有 shell history）"},
	{cmd: "help", fn: builtinNoop},
	{cmd: "man", alt: "help（这台机器上敲 help 看允许的命令）"},
	{cmd: "alias", alt: "不支持（别名会让白名单失效）"},
	{cmd: "unalias", alt: "不支持"},
	{cmd: "type", alt: "Get-Command"},
	{cmd: "export", alt: "无对应实现（每次执行是独立进程，环境变量不继承）"},
	{cmd: "unset", alt: "无对应实现"},
	{cmd: "xargs", alt: "无对应实现（没有管道语义）"},
	{cmd: "time", alt: "Measure-Command（需要包一层脚本块，不翻译）"},
	{cmd: "bc", alt: "无对应实现"},
	{cmd: "eject", alt: "无对应实现"},
	{cmd: "watch", alt: "无对应实现（周期性刷新需要终端）"},

	// ── 系统管理与性能监视 ──
	{cmd: "vmstat", alt: "Get-Counter（计数器模型不同）"},
	{cmd: "mpstat", alt: "Get-Counter"},
	{cmd: "iostat", alt: "Get-Counter"},
	{cmd: "sar", alt: "Get-Counter"},
	{cmd: "ipcs", alt: "无对应实现"},
	{cmd: "ipcrm", alt: "无对应实现"},
	{cmd: "chkconfig", alt: "Get-Service（启动类型用 Set-Service，属变更）"},

	// ── 进程管理 ──
	{cmd: "ps", fn: func(argv []string) ([]string, error) {
		_, pos := flagsPos(argv)
		if len(pos) > 0 {
			return []string{"Get-Process", "-Name", pos[0]}, nil
		}
		return []string{"Get-Process"}, nil
	}},
	{cmd: "pgrep", fn: func(argv []string) ([]string, error) {
		return need1(argv, "Get-Process", "-Name")
	}},
	{cmd: "kill", fn: xlateKill},
	{cmd: "killall", fn: xlateKillByName},
	{cmd: "pkill", fn: xlateKillByName},
	{cmd: "service", fn: xlateService},
	{cmd: "systemctl", fn: xlateService},
	{cmd: "pstree", alt: "Get-Process（没有树状视图）"},
	{cmd: "nice", alt: "无对应实现"},
	{cmd: "renice", alt: "无对应实现"},
	{cmd: "nohup", alt: "无对应实现（每次执行是独立请求，没有后台作业）"},
	{cmd: "bg", alt: "无对应实现（没有作业控制）"},
	{cmd: "fg", alt: "无对应实现（没有作业控制）"},
	{cmd: "jobs", alt: "无对应实现（没有作业控制）"},
	{cmd: "runlevel", alt: "无对应实现"},
	{cmd: "crontab", alt: "无对应实现（计划任务属变更，禁止）"},

	// ── 日志与服务（文章没列但运维离不开） ──
	{cmd: "journalctl", fn: func(argv []string) ([]string, error) {
		n := 50
		for i := 1; i < len(argv); i++ {
			if argv[i] == "-n" && i+1 < len(argv) {
				if v, err := strconv.Atoi(argv[i+1]); err == nil {
					n = v
				}
			}
		}
		return []string{"Get-EventLog", "-LogName", "Application", "-Newest", strconv.Itoa(n)}, nil
	}},
	{cmd: "docker", fn: passthrough},
	{cmd: "env", fn: func(argv []string) ([]string, error) {
		return []string{"Get-ChildItem", "Env:"}, nil
	}},

	// ── 规则集已经 deny 的高危命令 ──
	//
	// 翻译层其实不会被调用到（规则集先拒了），列在这里是为了让 help 能说清
	// "为什么不行"，而不是只回一句"不在白名单"。
	{cmd: "telnet", alt: "禁止（明文远程登录）"},
	{cmd: "ssh", alt: "禁止（远程登录）"},
	{cmd: "scp", alt: "禁止（远程传文件）"},
	{cmd: "wget", alt: "禁止（下载）"},
	{cmd: "curl", alt: "禁止（下载）"},
	{cmd: "nc", alt: "禁止（可反弹 shell）"},
	{cmd: "nmap", alt: "禁止（扫描）"},
	{cmd: "tcpdump", alt: "禁止（抓包）"},
	{cmd: "mail", alt: "禁止（外发）"},
	{cmd: "mutt", alt: "禁止（外发）"},
	{cmd: "rpm", alt: "禁止（装包）"},
	{cmd: "yum", alt: "禁止（装包）"},
	{cmd: "apt", alt: "禁止（装包）"},
	{cmd: "useradd", alt: "禁止（改账号）"},
	{cmd: "userdel", alt: "禁止（改账号）"},
	{cmd: "usermod", alt: "禁止（改账号）"},
	{cmd: "groupadd", alt: "禁止（改账号）"},
	{cmd: "passwd", alt: "禁止（改口令）"},
	{cmd: "chage", alt: "禁止（改口令）"},
	{cmd: "su", alt: "禁止（提权）"},
	{cmd: "sudo", alt: "禁止（提权）"},
	{cmd: "visudo", alt: "禁止（提权）"},
	{cmd: "shutdown", alt: "禁止（关机）"},
	{cmd: "halt", alt: "禁止（关机）"},
	{cmd: "poweroff", alt: "禁止（关机）"},
	{cmd: "reboot", alt: "禁止（重启）"},
	{cmd: "init", alt: "禁止（切运行级别）"},
	{cmd: "exec", alt: "禁止（进程替换）"},
	{cmd: "strace", alt: "禁止（跟踪调试）"},
	{cmd: "ltrace", alt: "禁止（跟踪调试）"},
	{cmd: "awk", alt: "禁止（脚本语言）"},
	{cmd: "sed", alt: "禁止（脚本语言）"},
}

// Translator 翻译器：Linux argv → Windows argv。
type Translator struct {
	index map[string]xlate
	order []string
}

// NewTranslator 建索引。
func NewTranslator() *Translator {
	t := &Translator{index: make(map[string]xlate, len(xlateTable))}
	for _, x := range xlateTable {
		if _, dup := t.index[x.cmd]; dup {
			panic("duplicate xlate entry: " + x.cmd)
		}
		t.index[x.cmd] = x
		t.order = append(t.order, x.cmd)
	}
	return t
}

var defaultTranslator = NewTranslator()

// Translate 把 Linux argv 翻成 Windows argv。
//
// 没有对应实现时返回 ErrNoWindowsEquivalent（调用方应把它当"拒绝执行"处理，
// 并把 Alt 原样告诉用户）。
func Translate(argv []string) ([]string, error) { return defaultTranslator.Translate(argv) }

func (t *Translator) Translate(argv []string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty argv")
	}
	name := trimExecExt(path.Base(strings.ReplaceAll(argv[0], "\\", "/")))
	x, ok := t.index[name]
	if !ok || x.fn == nil {
		return nil, &ErrNoWindowsEquivalent{Cmd: name, Alt: x.alt}
	}
	out, err := x.fn(argv)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, &ErrNoWindowsEquivalent{Cmd: name, Alt: x.alt}
	}
	return out, nil
}

// IsBuiltin 这条命令是会话内置的（cd/pwd/help），不需要下发到 agent。
func IsBuiltin(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch trimExecExt(path.Base(strings.ReplaceAll(argv[0], "\\", "/"))) {
	case "cd", "pwd", "help":
		return true
	}
	return false
}

// Mappings 导出对照表（给 /api/rules 展示"敲什么 → 实际跑什么"）。
func Mappings() []Mapping {
	out := make([]Mapping, 0, len(xlateTable))
	for _, name := range defaultTranslator.order {
		x := defaultTranslator.index[name]
		m := Mapping{Linux: name}
		switch {
		case IsBuiltin([]string{name}):
			m.Note = "会话内置：只改会话状态，不下发到机器"
		case x.fn == nil:
			m.Note = x.alt
		default:
			m.Windows = previewWindows(name)
		}
		out = append(out, m)
	}
	return out
}

// previewWindows 取该命令的 Windows 形态（跑一个最简单的样例输入，只为展示）。
func previewWindows(cmd string) string {
	sample := map[string][]string{
		"cat": {"cat", "a.log"}, "head": {"head", "-n", "20", "a.log"},
		"tail": {"tail", "-n", "20", "a.log"}, "grep": {"grep", "err", "a.log"},
		"find": {"find", ".", "-name", "*.log"}, "ls": {"ls"},
		"ps": {"ps"}, "kill": {"kill", "123"}, "wc": {"wc", "-l", "a.log"},
		"which": {"which", "nginx"}, "stat": {"stat", "a.log"},
		"mkdir": {"mkdir", "d"}, "cp": {"cp", "a", "b"}, "mv": {"mv", "a", "b"},
		"rm": {"rm", "a"}, "touch": {"touch", "a"}, "ping": {"ping", "-c", "4", "h"},
		"service": {"service", "nginx", "status"}, "systemctl": {"systemctl", "status", "nginx"},
		"du": {"du", "-sh", "."}, "df": {"df", "-h"}, "sort": {"sort", "a"},
		"uniq": {"uniq", "a"}, "diff": {"diff", "a", "b"}, "dig": {"dig", "a.com"},
		"basename": {"basename", "a/b.txt"}, "dirname": {"dirname", "a/b.txt"},
		"md5sum": {"md5sum", "a"}, "traceroute": {"traceroute", "a.com"},
		"journalctl": {"journalctl", "-n", "50"},
		"rename":     {"rename", "a", "b"}, "rmdir": {"rmdir", "d"},
		"egrep": {"egrep", "err", "a.log"}, "whereis": {"whereis", "nginx"},
		"ip": {"ip", "addr"}, "host": {"host", "a.com"},
		"pgrep": {"pgrep", "nginx"}, "killall": {"killall", "nginx"}, "pkill": {"pkill", "nginx"},
		"env": {"env"}, "id": {"id"}, "who": {"who"}, "clear": {"clear"},
	}
	argv, ok := sample[cmd]
	if !ok {
		argv = []string{cmd}
	}
	out, err := defaultTranslator.Translate(argv)
	if err != nil {
		return ""
	}
	return strings.Join(out, " ")
}

// ── 具体翻译函数 ──

// builtinNoop 会话内置命令：不产生 Windows argv（返回空表示"不需要下发"）。
//
// Translate 遇到空结果会返回 ErrNoWindowsEquivalent，所以调用方必须先过
// IsBuiltin——这里只是占位，保证表里每条都有 fn。
func builtinNoop(argv []string) ([]string, error) { return []string{"#builtin"}, nil }

// passthrough 命令名两边都有（hostname / whoami / nslookup / docker）。
func passthrough(argv []string) ([]string, error) { return argv, nil }

func xlateLs(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	out := []string{"Get-ChildItem"}
	if len(pos) > 0 {
		out = append(out, "-Path", pos[0])
	}
	if hasFlag(flags, "aA") {
		out = append(out, "-Force")
	}
	if hasFlag(flags, "Rr") {
		out = append(out, "-Recurse")
	}
	if hasFlag(flags, "l") {
		return append(out, "|", "Format-Table", "-AutoSize", "Mode,LastWriteTime,Length,Name"), nil
	}
	return out, nil
}

func xlateCat(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("cat: 需要文件名")
	}
	return append([]string{"Get-Content", "-Path"}, strings.Join(pos, ",")), nil
}

// takeNumFile 解析 `head -n 20 f` / `head -20 f` / `head f` 这几种写法。
//
// 注意 `-n` 的值是**下一个 argv 元素**，不是和 flag 连在一起的——所以不能只看
// 以 - 开头的元素，否则 `20` 会被当成文件名。
func takeNumFile(argv []string, cmd string) (n int, file string, follow bool, err error) {
	n = 10
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-n" || a == "-c":
			if i+1 >= len(argv) {
				return 0, "", false, errors.New(cmd + ": -n 缺数字")
			}
			if v, e := strconv.Atoi(argv[i+1]); e == nil {
				n = v
				i++
			}
		case a == "-f" || a == "-follow" || a == "--follow":
			follow = true
		case len(a) > 1 && a[0] == '-':
			// -20 / -n20 这种连写
			body := a[1:]
			body = strings.TrimPrefix(body, "n")
			if v, e := strconv.Atoi(body); e == nil {
				n = v
			}
		default:
			if file == "" {
				file = a
			}
		}
	}
	if file == "" {
		return 0, "", follow, errors.New(cmd + ": 需要文件名")
	}
	if n <= 0 || n > 100000 {
		return 0, "", follow, errors.New(cmd + ": 行数超出范围（1..100000）")
	}
	return n, file, follow, nil
}

func xlateHead(argv []string) ([]string, error) {
	n, file, _, err := takeNumFile(argv, "head")
	if err != nil {
		return nil, err
	}
	return []string{"Get-Content", "-Path", file, "-TotalCount", strconv.Itoa(n)}, nil
}

func xlateTail(argv []string) ([]string, error) {
	n, file, follow, err := takeNumFile(argv, "tail")
	if err != nil {
		return nil, err
	}
	if follow {
		return nil, errors.New("tail -f 是长驻跟踪，不支持（一次执行 = 一次快照）")
	}
	return []string{"Get-Content", "-Path", file, "-Tail", strconv.Itoa(n)}, nil
}

func xlateGrep(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("grep: 需要 pattern")
	}
	pattern := pos[0]
	// -r：递归要借 Get-ChildItem，Select-String 自己不带 -Recurse
	if hasFlag(flags, "rR") {
		dir := "."
		if len(pos) > 1 {
			dir = pos[1]
		}
		return []string{"Get-ChildItem", "-Path", dir, "-Recurse", "-File", "|",
			"Select-String", "-Pattern", pattern}, nil
	}
	out := []string{"Select-String", "-Pattern", pattern}
	if len(pos) > 1 {
		out = append(out, "-Path", pos[1])
	}
	if hasFlag(flags, "v") {
		out = append(out, "-NotMatch")
	}
	if hasFlag(flags, "c") {
		return nil, errors.New("grep -c 无对应实现（Select-String 输出里自己数）")
	}
	// -n：Select-String 默认带行号；-i：默认就不区分大小写；-E/-F 在参数语义上无差别
	return out, nil
}

func xlateFind(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("find: 需要路径")
	}
	out := []string{"Get-ChildItem", "-Path", pos[0], "-Recurse"}
	for i := 1; i < len(argv); i++ {
		switch argv[i] {
		case "-name":
			if i+1 >= len(argv) {
				return nil, errors.New("find -name: 缺参数")
			}
			out = append(out, "-Filter", argv[i+1])
			i++
		case "-type":
			if i+1 >= len(argv) {
				return nil, errors.New("find -type: 缺参数")
			}
			switch argv[i+1] {
			case "f":
				out = append(out, "-File")
			case "d":
				out = append(out, "-Directory")
			default:
				return nil, errors.New("find -type: 只支持 f / d")
			}
			i++
		case "-maxdepth":
			return nil, errors.New("find -maxdepth 在 Windows 上无对应实现")
		case "-delete", "-exec", "-ok":
			return nil, errors.New("find 的写类参数不支持（默认拒绝）")
		}
	}
	return out, nil
}

func xlateWc(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("wc: 需要文件名")
	}
	what := "-Line"
	switch {
	case hasFlag(flags, "w"):
		what = "-Word"
	case hasFlag(flags, "c"):
		what = "-Character"
	}
	return []string{"Get-Content", "-Path", pos[0], "|", "Measure-Object", what}, nil
}

func xlatePing(argv []string) ([]string, error) {
	out := []string{"ping"}
	host := ""
	for i := 1; i < len(argv); i++ {
		switch {
		case argv[i] == "-c": // Linux -c 次数 → Windows -n 次数
			if i+1 < len(argv) {
				if _, err := strconv.Atoi(argv[i+1]); err == nil {
					out = append(out, "-n", argv[i+1])
					i++
				}
			}
		case len(argv[i]) > 1 && argv[i][0] == '-':
			// 其余 flag 不翻译（Windows ping 的参数集不同，逐个映射只会出错）
		default:
			if host == "" {
				host = argv[i]
			}
		}
	}
	if host == "" {
		return nil, errors.New("ping: 需要目标主机")
	}
	return append(out, host), nil
}

func xlateIP(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("ip: 需要子命令（addr / route / link）")
	}
	// 改网络的写法（ip addr add ...）在这里再挡一次：规则集判过一次，
	// 翻译层不能装作没看见把它翻成"只看地址"。
	if len(pos) > 1 && isChangeVerb(pos[1]) {
		return nil, errors.New("ip: 改网络不翻译（只看不摸）")
	}
	switch pos[0] {
	case "addr", "address", "a":
		return []string{"Get-NetIPConfiguration"}, nil
	case "route", "r":
		return []string{"Get-NetRoute"}, nil
	case "link", "l":
		return []string{"Get-NetAdapter"}, nil
	}
	return nil, errors.New("ip: 只支持 addr / route / link 的查看（改网络不翻译）")
}

func xlateKill(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("kill: 需要进程号")
	}
	pid := pos[0]
	if _, err := strconv.Atoi(pid); err != nil {
		return nil, errors.New("kill: 进程号必须是数字（按名字杀用 pkill）")
	}
	out := []string{"Stop-Process", "-Id", pid}
	if hasFlag(flags, "9") {
		out = append(out, "-Force")
	}
	return out, nil
}

func xlateKillByName(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("pkill/killall: 需要进程名")
	}
	out := []string{"Stop-Process", "-Name", pos[0]}
	if hasFlag(flags, "9") {
		out = append(out, "-Force")
	}
	return out, nil
}

func xlateService(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	// systemctl status nginx（动作在前）与 service nginx status（动作在后）都要认
	if len(pos) < 2 {
		return nil, errors.New("service/systemctl: 需要 服务名 与 动作（status/start/stop/restart）")
	}
	act, name := pos[0], pos[1]
	if _, err := strconv.Atoi(act); err == nil || isAction(name) {
		act, name = name, act
	}
	if !isAction(act) {
		return nil, errors.New("service/systemctl: 只支持 status / start / stop / restart")
	}
	switch act {
	case "status":
		return []string{"Get-Service", "-Name", name}, nil
	case "start":
		return []string{"Start-Service", "-Name", name}, nil
	case "stop":
		return []string{"Stop-Service", "-Name", name}, nil
	case "restart":
		return []string{"Restart-Service", "-Name", name}, nil
	}
	return nil, errors.New("service/systemctl: 只支持 status / start / stop / restart")
}

// isChangeVerb 改网络的动作词。
func isChangeVerb(s string) bool {
	switch s {
	case "add", "del", "delete", "set", "change", "replace":
		return true
	}
	return false
}

func isAction(s string) bool {
	switch s {
	case "status", "start", "stop", "restart":
		return true
	}
	return false
}

func xlateCp(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) < 2 {
		return nil, errors.New("cp: 需要 源 与 目标")
	}
	out := []string{"Copy-Item", "-Path", pos[0], "-Destination", pos[1]}
	if hasFlag(flags, "rR") {
		out = append(out, "-Recurse")
	}
	return out, nil
}

func xlateMv(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) < 2 {
		return nil, errors.New("mv: 需要 源 与 目标")
	}
	return []string{"Move-Item", "-Path", pos[0], "-Destination", pos[1]}, nil
}

func xlateRename(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) < 2 {
		return nil, errors.New("rename: 需要 旧名 与 新名")
	}
	return []string{"Rename-Item", "-Path", pos[0], "-NewName", pos[1]}, nil
}

func xlateRm(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("rm: 需要路径")
	}
	out := []string{"Remove-Item", "-Path", pos[0]}
	if hasFlag(flags, "rR") {
		out = append(out, "-Recurse")
	}
	if hasFlag(flags, "f") {
		out = append(out, "-Force")
	}
	return out, nil
}

func xlateMkdir(argv []string) ([]string, error) {
	flags, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("mkdir: 需要目录名")
	}
	out := []string{"New-Item", "-ItemType", "Directory", "-Path", pos[0]}
	if hasFlag(flags, "p") {
		out = append(out, "-Force") // -p：父目录不存在就一起建
	}
	return out, nil
}

func xlateTouch(argv []string) ([]string, error) {
	_, pos := flagsPos(argv)
	if len(pos) == 0 {
		return nil, errors.New("touch: 需要文件名")
	}
	// 不加 -Force：文件已存在时报错，而不是把内容清空
	return []string{"New-Item", "-ItemType", "File", "-Path", pos[0]}, nil
}

// ── 小工具 ──

// flagsPos 把 argv[1:] 拆成标志与位置参数。
func flagsPos(argv []string) (flags []string, pos []string) {
	for _, a := range argv[1:] {
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			continue
		}
		pos = append(pos, a)
	}
	return
}

// hasFlag 判断标志里是否含某几个字母（支持 -la 这种合并写法）。
func hasFlag(flags []string, letters string) bool {
	for _, f := range flags {
		f = strings.TrimLeft(f, "-")
		for _, c := range f {
			if strings.ContainsRune(letters, c) {
				return true
			}
		}
	}
	return false
}

func firstPos(argv []string) string {
	_, pos := flagsPos(argv)
	if len(pos) == 0 {
		return ""
	}
	return pos[0]
}

// need1 形如 `basename x` → `Split-Path -Leaf x` 的固定映射。
func need1(argv []string, head ...string) ([]string, error) {
	p := firstPos(argv)
	if p == "" {
		return nil, errors.New(argv[0] + ": 需要参数")
	}
	return append(append([]string{}, head...), p), nil
}

// pipeFile `sort a.txt` → `Get-Content -Path a.txt | Sort-Object`。
func pipeFile(argv []string, tail string) ([]string, error) {
	p := firstPos(argv)
	if p == "" {
		return nil, errors.New(argv[0] + ": 需要文件名")
	}
	return []string{"Get-Content", "-Path", p, "|", tail}, nil
}

// CheckPipeline 复核翻译产物：管道每一段的**首命令**都必须被规则集放行。
//
// 用户敲的命令在 Linux 规则集里已经判过一次；这里再判的是"翻译模板吐出来的
// 东西"——模板里允许出现管道（比如 ls -l → Get-ChildItem | Format-Table），
// 但每一段都得是白名单里的，否则就是模板写错了。
func CheckPipeline(e *Engine, argv []string) error {
	segs := [][]string{{}}
	for _, a := range argv {
		if a == "|" {
			segs = append(segs, []string{})
			continue
		}
		segs[len(segs)-1] = append(segs[len(segs)-1], a)
	}
	for _, seg := range segs {
		if len(seg) == 0 {
			return errors.New("翻译结果里有空管道段")
		}
		if v := e.Check(seg); v.Decision != Allow {
			return fmt.Errorf("翻译结果的 %s 未被 Windows 规则集放行（%s）", seg[0], v.RuleID)
		}
	}
	return nil
}
