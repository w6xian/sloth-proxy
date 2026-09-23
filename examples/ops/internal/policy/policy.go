// Package policy 决定"能干什么、不能干什么"。
//
// 整个管控的地基是两条：
//  1. 命令以 argv 数组传递，**绝不经 shell 解释**——走 sh -c 就等于把白名单
//     交给 ; && | $()，任何正则都能被绕过；
//  2. 默认拒绝：没命中任何规则就是 deny，而不是"黑名单之外的都放行"。
package policy

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// Decision 策略判定结果。
type Decision string

const (
	// Allow 放行并记审计。
	Allow Decision = "allow"
	// Deny 拦截（同样记审计——谁在试探边界是最有价值的日志）。
	Deny Decision = "deny"
)

// Rule 一条规则。
//
// Cmd 匹配的是 argv[0] 的 basename（`ls` 而不是 `/bin/ls`），Args 匹配
// 参数拼成的整串（`strings.Join(argv[1:], " ")`），为空表示不约束参数。
type Rule struct {
	ID     string   `json:"id"`
	Cmd    string   `json:"cmd"`
	Args   string   `json:"args"`
	Effect Decision `json:"effect"`
	Reason string   `json:"reason"`
}

type compiledRule struct {
	Rule
	cmd  *regexp.Regexp
	args *regexp.Regexp
}

// Engine 规则引擎。规则按顺序匹配，命中第一条即生效。
type Engine struct {
	rules []compiledRule
}

// New 编译规则集。
func New(rules []Rule) (*Engine, error) {
	e := &Engine{}
	for _, r := range rules {
		cr := compiledRule{Rule: r}
		// 必须用 (?: ) 包住整个交替式：写成 "^a|b|c$" 的话，^ 与 $ 只锚住
		// 首尾两个分支，中间的 b 会退化成"子串包含匹配"——`at` 能命中
		// `Get-Date`，`su` 能命中任何名字里带 su 的命令。
		re, err := regexp.Compile("^(?:" + r.Cmd + ")$")
		if err != nil {
			return nil, errors.New("rule " + r.ID + ": bad cmd pattern: " + err.Error())
		}
		cr.cmd = re
		if r.Args != "" {
			re, err := regexp.Compile("^(?:" + r.Args + ")$")
			if err != nil {
				return nil, errors.New("rule " + r.ID + ": bad args pattern: " + err.Error())
			}
			cr.args = re
		}
		e.rules = append(e.rules, cr)
	}
	return e, nil
}

// Verdict 判定结果，带命中的规则 ID 与理由（进审计）。
type Verdict struct {
	Decision Decision
	RuleID   string
	Reason   string
}

// Check 判定一条命令。默认拒绝：无规则命中即 Deny。
func (e *Engine) Check(argv []string) Verdict {
	if len(argv) == 0 {
		return Verdict{Decision: Deny, RuleID: "empty", Reason: "empty command"}
	}
	name := trimExecExt(path.Base(strings.ReplaceAll(argv[0], "\\", "/")))
	args := strings.Join(argv[1:], " ")
	for _, r := range e.rules {
		if !r.cmd.MatchString(name) {
			continue
		}
		if r.args != nil && !r.args.MatchString(args) {
			continue
		}
		return Verdict{Decision: r.Effect, RuleID: r.ID, Reason: r.Reason}
	}
	return Verdict{Decision: Deny, RuleID: "default", Reason: "not in whitelist (default deny)"}
}

// trimExecExt 剥掉 Windows 可执行后缀。
//
// `sc.exe` 与 `sc` 是同一条命令；不归一化的话，`^sc$` 这条 deny 会被
// `C:\Windows\System32\sc.exe` 直接绕过去。
func trimExecExt(name string) string {
	lower := strings.ToLower(name)
	for _, ext := range []string{".exe", ".com", ".bat", ".cmd"} {
		if strings.HasSuffix(lower, ext) && len(name) > len(ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

// 档位：只决定"能执行哪些命令"，与审计无关——任何档位的任何请求（含被拒的）都记。
const (
	LevelView  = "view"
	LevelOps   = "ops"
	LevelAdmin = "admin"
)

// 平台：agent 上报的 runtime.GOOS。规则集**按平台分开**，因为
// `ls`/`cat`/`grep` 在 Windows 上根本不存在，而 `dir`/`type` 又是 cmd 内置
// （不是可执行文件，exec 找不到）——拿 Linux 白名单去管 Windows，
// 结果就是"判定 allow、执行 not found in %PATH%"。
const (
	PlatformLinux   = "linux"
	PlatformWindows = "windows"
)

// IsWindows 判平台；未知平台按 Linux 处理（最保守的那套）。
func IsWindows(platform string) bool {
	p := strings.ToLower(strings.TrimSpace(platform))
	return p == PlatformWindows || p == "win"
}

// pathChars 路径与参数里允许的字符：两套路径语法（`/var/log` 与 `C:\var\log`）
// 都吃得下——统一入口是 Linux 命令，但 Windows 上人得敲盘符路径。
//
// 真正的越界不靠它：靠 agent 的 -root。那里才是唯一真相，这里再写一份
// 路径规则只会变成第二套真相。
const pathChars = `[\w.:/\\ ~+-]*`

// baseDenyRules 任何档位都拒绝：这些一放开，白名单就被绕过去了。
//
// 覆盖运维常用命令里的全部**变更类**：改权限、改账号、改磁盘、远程登录、
// 装包、抓包扫描、解释器、关机、跟踪调试。
var baseDenyRules = []Rule{
	{ID: "deny-boot", Cmd: `shutdown|reboot|halt|poweroff|init|telinit`, Effect: Deny, Reason: "关机/重启类禁止"},
	{ID: "deny-perm", Cmd: `chmod|chown|chgrp|umask|setfacl|chattr|lsattr`, Effect: Deny, Reason: "权限与属性变更禁止"},
	{ID: "deny-user", Cmd: `useradd|userdel|usermod|groupadd|passwd|chage|su|sudo|visudo`, Effect: Deny, Reason: "账号与提权类禁止"},
	{ID: "deny-shell", Cmd: `sh|bash|zsh|ksh|fish|python|python3|perl|ruby|node|php|awk|sed`,
		Effect: Deny, Reason: "解释器与脚本语言禁止（等于绕过白名单）"},
	{ID: "deny-remote", Cmd: `curl|wget|nc|ncat|ssh|scp|sftp|rsync|ftp|telnet|nmap|tcpdump|mail|mutt`,
		Effect: Deny, Reason: "下载/远程/扫描/抓包类禁止"},
	{ID: "deny-pkg", Cmd: `apt|apt-get|yum|dnf|rpm|dpkg|pip|npm`, Effect: Deny, Reason: "安装与包管理禁止"},
	{ID: "deny-disk", Cmd: `mount|umount|mkfs|mkswap|swapon|swapoff|fdisk|parted|partprobe|fsck|e2fsck|dumpe2fs|dump|resize2fs|dd`,
		Effect: Deny, Reason: "磁盘与文件系统变更禁止"},
	{ID: "deny-trace", Cmd: `strace|ltrace|gdb|perf`, Effect: Deny, Reason: "跟踪/调试类禁止"},
	{ID: "deny-detach", Cmd: `exec|eval|source|nohup|setsid`, Effect: Deny, Reason: "进程替换与脱离控制类禁止"},
}

// interactiveDenyRules 需要真终端（pty）的命令。
//
// 这里每次执行是一次 RPC，没有可交互的终端，跑起来只会挂到超时——
// 明确拒绝并给替代命令，比让人等 10 秒超时要好。
var interactiveDenyRules = []Rule{
	{ID: "deny-interactive", Cmd: `top|htop|atop|watch|less|more|vi|vim|nano|vimdiff|man|info`,
		Effect: Deny, Reason: "需要交互式终端（没有 pty）；改用 ps / head / tail / cat"},
}

// argDenyRules 参数级拒绝：命令本身可以放行，但某几个参数不行。
//
// 必须在对应的 allow 之前命中（Check 命中第一条即生效），所以放在 viewRules 前面。
var argDenyRules = []Rule{
	{ID: "deny-find-write", Cmd: `find`, Args: `(.* )?-(delete|exec|execdir|ok|okdir|fprintf|fls)( .*)?`,
		Effect: Deny, Reason: "find 的写类参数禁止"},
	{ID: "deny-tail-follow", Cmd: `tail`, Args: `(.* )?-f(ollow)?( .*)?`, Effect: Deny, Reason: "tail -f 是长驻跟踪，不支持"},
	{ID: "deny-ip-change", Cmd: `ip`, Args: `.*(addr|address|a|link|l) (add|del|set|change)( .*)?`,
		Effect: Deny, Reason: "ip 的改网络参数禁止"},
	{ID: "deny-grep-recursive-unsafe", Cmd: `grep|egrep`, Args: `.*-r.*-I.*`, Effect: Deny, Reason: "参数组合过多，不逐条放行"},
}

// destructiveDenyRules 写与删除：view / ops 档禁止；admin 档只放开受约束的那几条。
var destructiveDenyRules = []Rule{
	{ID: "deny-rm", Cmd: `rm|rmdir|shred`, Effect: Deny, Reason: "删除类禁止（当前档位），清理走审批过的任务"},
	{ID: "deny-write", Cmd: `mv|cp|rename|mkdir|touch|truncate|install`, Effect: Deny, Reason: "写操作禁止（当前档位）"},
	{ID: "deny-archive", Cmd: `tar|zip|unzip|gzip|gunzip|split`, Effect: Deny, Reason: "压缩解压禁止（会覆盖文件）"},
}

// viewRules 只读观测：三个档位都有。以 Linux 运维常用命令为准。
var viewRules = []Rule{
	// 目录与文件
	{ID: "allow-ls", Cmd: `ls|tree`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-cat", Cmd: `cat|tac|rev`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-head", Cmd: `head`, Args: `(-n ?\d{1,4}|\d{1,4})? ?[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-tail", Cmd: `tail`, Args: `(-n ?\d{1,4}|\d{1,4})? ?[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-grep", Cmd: `grep|egrep|fgrep`, Args: `.*`, Effect: Allow},
	{ID: "allow-find", Cmd: `find`, Args: `[\w.:/\\ ~*+-]*( -name [\w.*+-]+)?( -type [fd])?( -maxdepth \d{1,3})?`, Effect: Allow},
	{ID: "allow-which", Cmd: `which|whereis|type`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-locate", Cmd: `locate|updatedb`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-stat", Cmd: `stat|file|md5sum|sha1sum|sha256sum|basename|dirname`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-text", Cmd: `wc|sort|uniq|cut|paste|join|diff|iconv|dos2unix|tr`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	// 进程与系统
	{ID: "allow-ps", Cmd: `ps|pgrep|pstree`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-df", Cmd: `df|du|free|vmstat|iostat|mpstat|sar`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-id", Cmd: `whoami|id|hostname|uname|uptime|date|cal|env|dmesg|last|lastlog|who|w|users|finger`,
		Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-echo", Cmd: `echo|printf|clear|sync|bc|export|unset|xargs|time|eject|alias|unalias|history|help`,
		Args: `.*`, Effect: Allow, Reason: "无副作用的壳内命令（每次执行是独立进程，export/alias 只对这一次有效）"},
	// 网络（只读）
	{ID: "allow-socket", Cmd: `netstat|ss|lsof`, Args: `[\w\s-]*`, Effect: Allow},
	{ID: "allow-ifconfig", Cmd: `ifconfig|route`, Args: `[\w\s-]*`, Effect: Allow},
	{ID: "allow-ip-show", Cmd: `ip`, Args: `(-[a-z0-9]+ )*(addr|address|a|route|r|link|l|neigh|n)( show)?`,
		Effect: Allow, Reason: "ip 只允许查看类子命令"},
	{ID: "allow-ping", Cmd: `ping|traceroute|tracepath|mtr`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	{ID: "allow-dns", Cmd: `nslookup|dig|host`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow},
	// 服务与容器（只读）
	{ID: "allow-svc-status", Cmd: `systemctl|service`, Args: `status [\w.:-]+|[\w.:-]+ status`, Effect: Allow,
		Reason: "服务只看状态"},
	{ID: "allow-journalctl", Cmd: `journalctl`, Args: `(-n \d{1,4}( -u [\w.-]+)?|-u [\w.-]+( -n \d{1,4})?)`, Effect: Allow},
	{ID: "allow-docker", Cmd: `docker`, Args: `ps.*|images.*|logs (--tail \d{1,4} )?[\w.-]+|inspect [\w.-]+`, Effect: Allow},
	{ID: "allow-chkconfig", Cmd: `chkconfig`, Args: `--list.*`, Effect: Allow},
}

// builtinRules 会话内置命令：**不进子进程**，由 gate 自己处理。
//
// cd 没有可执行文件（是 shell 内置），pwd 交给子进程跑也没意义——
// 工作目录本来就是会话状态。放这里让它们仍在白名单里受档位约束：
// 某档位没加载这条规则，cd/pwd 就是默认拒绝。
var builtinRules = []Rule{
	{ID: "allow-pwd", Cmd: `pwd`, Effect: Allow, Reason: "会话内置：返回会话当前目录，不进子进程"},
	{ID: "allow-cd", Cmd: `cd`, Args: `[\w.:/\\ ~+-]*`, Effect: Allow,
		Reason: "会话内置：只改会话 cwd，越界由 agent 的 -root 挡"},
}

// opsRules 进程与服务操作：起停按名，杀进程按 pid/名。
var opsRules = []Rule{
	{ID: "allow-svc-ctl", Cmd: `systemctl|service`,
		Args:   `(start|stop|restart|reload) [\w.:-]+|[\w.:-]+ (start|stop|restart|reload)`,
		Effect: Allow, Reason: "服务起停（按名）"},
	{ID: "allow-kill", Cmd: `kill`, Args: `(-9 |-15 |-TERM |-KILL )?\d+`, Effect: Allow, Reason: "按 pid 杀进程"},
	{ID: "allow-kill-name", Cmd: `killall|pkill`, Args: `(-9 |-15 )?[\w.:-]+`, Effect: Allow, Reason: "按名字杀进程"},
	{ID: "allow-nice", Cmd: `nice|renice`, Args: `(-n -?\d{1,2} )?[\w.:-]+`, Effect: Allow},
	{ID: "allow-crontab-list", Cmd: `crontab`, Args: `-l.*`, Effect: Allow, Reason: "只看计划任务列表"},
	{ID: "allow-docker-ctl", Cmd: `docker`, Args: `(start|stop|restart) [\w.-]+`, Effect: Allow},
}

// adminRules 管理员档：放开**受约束**的写与删除（限定在数据目录内）。
//
// 路径同时接受 Linux 与 Windows 两种写法：入口是统一的 Linux 命令，
// 但 Windows 机器上人只能敲 `C:\data\tmp\...`。
var adminRules = []Rule{
	{ID: "allow-rm-tmp", Cmd: `rm|rmdir`,
		Args: `(-[rf]+ )?(/data/tmp/|[A-Za-z]:\\data\\tmp\\)[\w.:/\\ ~+-]+`, Effect: Allow,
		Reason: "仅允许清理 data/tmp"},
	{ID: "allow-write-data", Cmd: `cp|mv|rename`,
		Args: `[\w.:/\\ ~+-]+ (/data/|[A-Za-z]:\\data\\)[\w.:/\\ ~+-]+`, Effect: Allow,
		Reason: "仅允许写进 data 目录"},
	{ID: "allow-mkdir-touch", Cmd: `mkdir|touch`,
		Args: `(-p )?(/data/|[A-Za-z]:\\data\\)[\w.:/\\ ~+-]*`, Effect: Allow,
		Reason: "仅允许在 data 目录下建目录/文件"},
}

// ── Windows 规则集 ──
//
// Windows 规则集**只用来复核翻译产物**，不再用来判用户输入。
//
// 入口已经是统一的 Linux 命令了：Windows 上直接敲 `Get-ChildItem` 会落在
// Linux 规则集的默认拒绝里——人拿到的是一套名字，而下发的命令仍要过一层
// 独立的白名单。这条缝的价值在于：万一某条翻译模板写错、吐出 Remove-Item
// 或 Invoke-*，这里能拦住，而不是让它真的跑在机器上。

// winDenyRules 复核时任何档位都拒绝：解释器、远程执行、提权、关机。
var winDenyRules = []Rule{
	{ID: "win-deny-host", Cmd: `cmd|cmd.exe|powershell|powershell.exe|pwsh|bash|wsl|python|python3|perl|ruby|node|rundll32|regsvr32|msiexec|installutil`,
		Effect: Deny, Reason: "解释器与脚本宿主禁止（等于绕过白名单）"},
	{ID: "win-deny-invoke", Cmd: `Invoke-Expression|Invoke-Command|Invoke-WebRequest|Invoke-RestMethod|Start-Process|Start-BitsTransfer|Set-ExecutionPolicy|Install-Module|Install-Package|Set-Alias|New-Object`,
		Effect: Deny, Reason: "执行/下载类 cmdlet 禁止"},
	{ID: "win-deny-boot", Cmd: `Stop-Computer|Restart-Computer|Reset-Computer|shutdown|logoff`, Effect: Deny, Reason: "关机/重启类禁止"},
	{ID: "win-deny-priv", Cmd: `net|net1|sc|reg|regedit|takeown|icacls|cipher|schtasks|at|wmic|vssadmin|bcdedit|wbadmin|diskpart|format|taskkill|ftp|tftp|telnet|curl|wget|nc|ssh|scp`,
		Effect: Deny, Reason: "账号/服务/计划任务/提权类禁止"},
}

// winReadRules 翻译产物白名单：只读 cmdlet + 两边同名的外部命令。
//
// 参数不在这里约束——翻译模板的参数是固定的，用户输入只能填进"值"的位置，
// 而值已经在 Linux 规则集那一步被参数正则判过了。
var winReadRules = []Rule{
	{ID: "win-allow-read", Cmd: `Get-ChildItem|Get-Item|Get-Content|Select-String|Get-Process|Get-Service|` +
		`Get-Command|Get-PSDrive|Get-Volume|Get-CimInstance|Get-Date|Get-ComputerInfo|Get-NetTCPConnection|` +
		`Get-NetIPConfiguration|Get-NetRoute|Get-NetAdapter|Get-FileHash|Get-EventLog|Get-WinEvent|` +
		`Get-Location|Test-Path`, Effect: Allow},
	// 管道后半段出现的那几个（ls -l → Get-ChildItem | Format-Table）
	{ID: "win-allow-pipe", Cmd: `Split-Path|Measure-Object|Compare-Object|Sort-Object|Get-Unique|` +
		`Format-Table|Format-List|Select-Object|Where-Object|Out-String|Write-Output|Clear-Host|Resolve-DnsName`,
		Effect: Allow},
	{ID: "win-allow-exe", Cmd: `ping|tracert|nslookup|ipconfig|hostname|whoami|quser|docker`, Effect: Allow},
}

// winOpsRules 翻译产物里的进程与服务操作。
var winOpsRules = []Rule{
	{ID: "win-allow-svcctl", Cmd: `Start-Service|Stop-Service|Restart-Service`, Effect: Allow},
	{ID: "win-allow-kill", Cmd: `Stop-Process`, Effect: Allow},
}

// winWriteRules 翻译产物里的写类 cmd程度：只有 admin 档才可能出现
// （Linux 侧已先判过路径约束，这里是第二道）。
var winWriteRules = []Rule{
	{ID: "win-allow-write", Cmd: `New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item`, Effect: Allow},
}

// RulesFor 按档位 + 平台取规则集。
//
// 顺序有意义：baseDeny 在最前，避免高危命令被后面的放行规则"捞回去"；
// 未命中任何规则即默认拒绝（见 Check）。
func RulesFor(level, platform string) []Rule {
	lv := strings.ToLower(strings.TrimSpace(level))
	// Windows 那套只用于复核翻译产物，所以没有 destructive/builtin 分层
	if IsWindows(platform) {
		switch lv {
		case LevelOps:
			return concatRules(winDenyRules, winReadRules, winOpsRules)
		case LevelAdmin:
			return concatRules(winDenyRules, winReadRules, winOpsRules, winWriteRules)
		default:
			return concatRules(winDenyRules, winReadRules)
		}
	}
	switch lv {
	case LevelOps:
		return concatRules(baseDenyRules, interactiveDenyRules, argDenyRules,
			destructiveDenyRules, viewRules, builtinRules, opsRules)
	case LevelAdmin:
		return concatRules(baseDenyRules, interactiveDenyRules, argDenyRules,
			viewRules, builtinRules, opsRules, adminRules)
	default: // view：最保守，未知档位也按它处理
		return concatRules(baseDenyRules, interactiveDenyRules, argDenyRules,
			destructiveDenyRules, viewRules, builtinRules)
	}
}

// RulesForLevel 按档位取 Linux 规则集。新代码请用 RulesFor（带平台）。
func RulesForLevel(level string) []Rule { return RulesFor(level, PlatformLinux) }

// DefaultRules 最保守的一档。新代码请用 RulesFor。
func DefaultRules() []Rule { return RulesForLevel(LevelView) }

func concatRules(sets ...[]Rule) []Rule {
	var out []Rule
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// ErrShellSyntax 输入含 shell 元字符：不支持，请用脚本模板。
var ErrShellSyntax = errors.New("不支持 shell 语法（; | & $ ` < > 等），请用脚本模板")

// ParseLine 把一行输入切成 argv。
//
// 不做任何 shell 解释：只按空白切分并支持引号包裹，遇到元字符直接报错。
// 这是白名单能拦得住的前提——shell 一介入，规则再多也是摆设。
func ParseLine(line string) ([]string, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, errors.New("empty command line")
	}
	for _, r := range trimmed {
		switch r {
		case ';', '|', '&', '$', '`', '<', '>', '(', ')', '{', '}', '\n', '\r', '\t':
			return nil, ErrShellSyntax
		}
	}
	var (
		out    []string
		cur    strings.Builder
		quoted bool
		quote  byte
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case quoted:
			if c == quote {
				quoted = false
				continue
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quoted, quote = true, c
		case c == ' ':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	if quoted {
		return nil, errors.New("引号未闭合")
	}
	flush()
	if len(out) == 0 {
		return nil, errors.New("empty command line")
	}
	return out, nil
}
