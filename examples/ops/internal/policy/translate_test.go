package policy

import (
	"strings"
	"testing"
)

// TestTranslate 核心映射：Linux 命令 → Windows 命令。
func TestTranslate(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{[]string{"ls"}, "Get-ChildItem"},
		{[]string{"ls", "-a"}, "Get-ChildItem -Force"},
		{[]string{"ls", "/var/log"}, "Get-ChildItem -Path /var/log"},
		{[]string{"ls", "-l"}, "Get-ChildItem | Format-Table -AutoSize Mode,LastWriteTime,Length,Name"},
		{[]string{"ls", "-R"}, "Get-ChildItem -Recurse"},
		{[]string{"cat", "a.log"}, "Get-Content -Path a.log"},
		{[]string{"head", "-n", "20", "a.log"}, "Get-Content -Path a.log -TotalCount 20"},
		{[]string{"head", "-20", "a.log"}, "Get-Content -Path a.log -TotalCount 20"},
		{[]string{"head", "a.log"}, "Get-Content -Path a.log -TotalCount 10"},
		{[]string{"tail", "-n", "50", "a.log"}, "Get-Content -Path a.log -Tail 50"},
		{[]string{"grep", "err", "a.log"}, "Select-String -Pattern err -Path a.log"},
		{[]string{"grep", "-v", "err", "a.log"}, "Select-String -Pattern err -Path a.log -NotMatch"},
		{[]string{"grep", "-r", "err", "/data"},
			"Get-ChildItem -Path /data -Recurse -File | Select-String -Pattern err"},
		{[]string{"find", ".", "-name", "*.log"}, "Get-ChildItem -Path . -Recurse -Filter *.log"},
		{[]string{"find", "/data", "-type", "f"}, "Get-ChildItem -Path /data -Recurse -File"},
		{[]string{"wc", "-l", "a.log"}, "Get-Content -Path a.log | Measure-Object -Line"},
		{[]string{"sort", "a.log"}, "Get-Content -Path a.log | Sort-Object"},
		{[]string{"uniq", "a.log"}, "Get-Content -Path a.log | Get-Unique"},
		{[]string{"diff", "a", "b"}, "Compare-Object (Get-Content a) (Get-Content b)"},
		{[]string{"ps"}, "Get-Process"},
		{[]string{"ps", "-Name", "nginx"}, "Get-Process -Name nginx"},
		{[]string{"df", "-h"}, "Get-PSDrive -PSProvider FileSystem"},
		{[]string{"du", "-sh", "."}, "Get-ChildItem -Path . -Recurse -File | Measure-Object -Property Length -Sum"},
		{[]string{"free"}, "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory"},
		{[]string{"uptime"}, "Get-CimInstance Win32_OperatingSystem | Select-Object LastBootUpTime"},
		{[]string{"uname", "-a"}, "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber"},
		{[]string{"date"}, "Get-Date"},
		{[]string{"hostname"}, "hostname"},
		{[]string{"whoami"}, "whoami"},
		{[]string{"id"}, "whoami /groups"},
		{[]string{"env"}, "Get-ChildItem Env:"},
		{[]string{"echo", "hi"}, "Write-Output hi"},
		{[]string{"clear"}, "Clear-Host"},
		{[]string{"which", "nginx"}, "Get-Command -Name nginx"},
		{[]string{"stat", "a.log"}, "Get-Item -Path a.log"},
		{[]string{"basename", "a/b.txt"}, "Split-Path -Leaf a/b.txt"},
		{[]string{"dirname", "a/b.txt"}, "Split-Path -Parent a/b.txt"},
		{[]string{"md5sum", "a"}, "Get-FileHash -Algorithm MD5 -Path a"},
		{[]string{"tree"}, "Get-ChildItem -Recurse"},
		{[]string{"ping", "-c", "4", "a.com"}, "ping -n 4 a.com"},
		{[]string{"ping", "a.com"}, "ping a.com"},
		{[]string{"netstat", "-tulpn"}, "Get-NetTCPConnection"},
		{[]string{"ss", "-lntp"}, "Get-NetTCPConnection"},
		{[]string{"ifconfig"}, "Get-NetIPConfiguration"},
		{[]string{"ip", "addr"}, "Get-NetIPConfiguration"},
		{[]string{"ip", "route"}, "Get-NetRoute"},
		{[]string{"route"}, "Get-NetRoute"},
		{[]string{"dig", "a.com"}, "Resolve-DnsName -Name a.com"},
		{[]string{"nslookup", "a.com"}, "nslookup a.com"},
		{[]string{"traceroute", "a.com"}, "tracert a.com"},
		{[]string{"kill", "123"}, "Stop-Process -Id 123"},
		{[]string{"kill", "-9", "123"}, "Stop-Process -Id 123 -Force"},
		{[]string{"pkill", "nginx"}, "Stop-Process -Name nginx"},
		{[]string{"killall", "-9", "nginx"}, "Stop-Process -Name nginx -Force"},
		{[]string{"systemctl", "status", "nginx"}, "Get-Service -Name nginx"},
		{[]string{"service", "nginx", "restart"}, "Restart-Service -Name nginx"},
		{[]string{"systemctl", "stop", "nginx"}, "Stop-Service -Name nginx"},
		{[]string{"journalctl", "-n", "50"}, "Get-EventLog -LogName Application -Newest 50"},
		{[]string{"docker", "ps"}, "docker ps"},
		{[]string{"cp", "a.txt", "/data/b.txt"}, "Copy-Item -Path a.txt -Destination /data/b.txt"},
		{[]string{"cp", "-r", "src", "/data/dst"}, "Copy-Item -Path src -Destination /data/dst -Recurse"},
		{[]string{"mv", "a.txt", "/data/b.txt"}, "Move-Item -Path a.txt -Destination /data/b.txt"},
		{[]string{"rm", "-rf", "/data/tmp/x"}, "Remove-Item -Path /data/tmp/x -Recurse -Force"},
		{[]string{"mkdir", "-p", "/data/x"}, "New-Item -ItemType Directory -Path /data/x -Force"},
		{[]string{"touch", "/data/x"}, "New-Item -ItemType File -Path /data/x"},
		{[]string{"rename", "a", "b"}, "Rename-Item -Path a -NewName b"},
	}
	for _, c := range cases {
		got, err := Translate(c.in)
		if err != nil {
			t.Errorf("%v: %v", c.in, err)
			continue
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%v:\n  got  %v\n  want %v", c.in, got, c.want)
		}
	}
}

// TestTranslateNoEquivalent Windows 上做不到的事，要明说并给替代命令。
func TestTranslateNoEquivalent(t *testing.T) {
	for _, argv := range [][]string{
		{"top"}, {"vim", "a"}, {"less", "a.log"}, {"tar", "-xf", "a.tar.gz"},
		{"lsof"}, {"crontab", "-e"}, {"mount"}, {"chmod", "777", "x"},
		{"xargs", "rm"}, {"watch", "ls"}, {"tcpdump"}, {"man", "ls"},
	} {
		_, err := Translate(argv)
		if err == nil {
			t.Errorf("%v: got nil error, want ErrNoWindowsEquivalent", argv)
			continue
		}
		var ne *ErrNoWindowsEquivalent
		if !errorsAs(err, &ne) {
			t.Errorf("%v: got %T, want ErrNoWindowsEquivalent", argv, err)
			continue
		}
		if ne.Alt == "" {
			t.Errorf("%v: 没有给替代命令提示", argv)
		}
	}
}

// errorsAs 小工具（避免为这一个断言引入 errors 包的写法噪音）。
func errorsAs(err error, target **ErrNoWindowsEquivalent) bool {
	ne, ok := err.(*ErrNoWindowsEquivalent)
	if ok {
		*target = ne
	}
	return ok
}

// TestTranslateRejects 翻译层自己也拒绝危险输入，而不是硬翻译成等价物。
func TestTranslateRejects(t *testing.T) {
	bad := [][]string{
		{"tail", "-f", "a.log"},      // 长驻
		{"find", "/data", "-delete"}, // 写类参数
		{"find", "/data", "-exec", "rm"},
		{"find", "/data", "-maxdepth", "2"}, // 没有对应实现
		{"kill", "nginx"},                   // kill 只收 pid
		{"grep"},                            // 缺 pattern
		{"cat"},                             // 缺文件名
		{"systemctl", "nginx"},              // 缺动作
		{"ip", "addr", "add", "1.2.3.4"},    // 改网络
	}
	for _, argv := range bad {
		if _, err := Translate(argv); err == nil {
			t.Errorf("%v: got nil, want error", argv)
		}
	}
}

// TestTranslateCoverage 对照表里每条都要有落点：要么能翻，要么给了替代建议。
func TestTranslateCoverage(t *testing.T) {
	for _, m := range Mappings() {
		if m.Windows == "" && m.Note == "" {
			t.Errorf("%s: 既没有 Windows 映射，也没有替代说明", m.Linux)
		}
	}
	// 文章里那批高频命令必须在表里
	for c, argv := range map[string][]string{
		"ls": {"ls"}, "cd": {"cd", "x"}, "pwd": {"pwd"}, "cp": {"cp", "a", "b"},
		"mv": {"mv", "a", "b"}, "rm": {"rm", "a"}, "mkdir": {"mkdir", "d"},
		"touch": {"touch", "a"}, "cat": {"cat", "a"}, "head": {"head", "a"},
		"tail": {"tail", "a"}, "grep": {"grep", "p", "a"}, "find": {"find", "."},
		"ps": {"ps"}, "kill": {"kill", "1"}, "df": {"df"}, "du": {"du", "."},
		"free": {"free"}, "top": {"top"}, "which": {"which", "x"}, "ping": {"ping", "h"},
		"netstat": {"netstat"}, "ifconfig": {"ifconfig"}, "systemctl": {"systemctl", "status", "x"},
		"service": {"service", "x", "status"}, "journalctl": {"journalctl"}, "docker": {"docker", "ps"},
		"tar": {"tar"}, "chmod": {"chmod"},
	} {
		if _, err := Translate(argv); err != nil {
			var ne *ErrNoWindowsEquivalent
			if errorsAs(err, &ne) && ne.Alt != "" {
				continue // 明确"不支持"也是落点
			}
			t.Errorf("%s: 对照表里没有落点（%v）", c, err)
		}
	}
}
