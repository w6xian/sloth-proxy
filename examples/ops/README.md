# sloth-proxy

基于 [sloth](https://github.com/w6xian/sloth) 的远程运维管控端：**Web 受限终端 + 命令级白名单 + 强制审计**。

定位：给"远程管理一批内网机器"用。机器上的 agent 主动外连，不需要公网 IP；
管理员在 Web 上敲命令，命令经策略判定后下发执行，**每一条都进审计**。

## 位置与依赖

本示例是 `sloth-proxy` 仓库的一个示例（`examples/ops`），没有自己的 `go.mod`：

- 命令统一从**仓库根**跑：`go run ./examples/ops/cmd/gate`；
- sloth 由仓库根的 `go.work`（`use . ..`）指向本地 `../v4` 源码，改 sloth 立刻生效；
  `go.work` 不提交，发布版依赖 sloth 的正式 tag（见仓库根 README「本地联调」）；
- 外部依赖只有一个 `golang.org/x/crypto/bcrypt`（口令哈希），已在仓库根 `go.mod` 里。

## 登录、授权与档位

三条互相独立的判据，依次生效：

| 环节 | 回答的问题 | 落在哪 |
|---|---|---|
| 登录（authn） | 你是谁 | `internal/authn`，默认内置账号表（bcrypt），可换 LDAP/OAuth |
| 授权（authz） | 你在这台机器上是什么档位 | `internal/authz`，`用户 × 机器 × 档位`，机器支持 `*` / `web*` 通配 |
| 策略（policy） | 这个档位能不能执行这条命令 | `internal/policy`，按档位加载规则集，默认拒绝（判定不分平台，见"统一命令层"） |

档位：`view`（只读观测）/ `ops`（+服务起停）/ `admin`（+受约束的删除与移动）。
**任何档位的任何请求都记审计**，包括被拒的。

配置（都是可选，缺省用内置默认 `demo/demo` + view 档）：

```bash
cp examples/ops/users.example.json  examples/ops/users.json   # 账号：pass(bcrypt) 或 pass_plain(明文,仅上手用)
cp examples/ops/grants.example.json examples/ops/grants.json  # 授权：user × machine × level
go run ./examples/ops/cmd/gate -users examples/ops/users.json -grants examples/ops/grants.json
```

未登录访问 `/api/*` 一律 401；机器列表只返回**有授权**的机器（列表本身也是信息）。

想知道"我在这台机器上能敲什么"：终端里敲 `help`（或 `?`、点"支持什么命令"按钮），
底层是 `GET /api/rules?machine=web01` —— 返回该机器 + 该档位的 allow/deny 规则集
（含每条的参数约束与理由）。未授权的机器只答 `granted:false`，不泄露规则。
Windows 机器上额外返回 `mappings`：**敲的 Linux 命令 → 实际跑的 Windows 命令**（174 条完整对照）。

```
浏览器（受限终端）──POST /api/exec──▶ gate
                                      ① 取操作者（登录态）
                                      ② 切成 argv，拒绝 shell 语法
                                      ③ 策略引擎判定（Linux 规则集，默认拒绝）
                                      ④ 审计落盘（放行与拒绝都记）
                                      ⑤ Windows 机器：翻译成 PowerShell + 复核产物
                                      ⑥ sloth: server.Call(userId, "ops.Exec", argv)
                                                        │
                                                        ▼
                                              agent（被管机，本地 exec）
```

- **没有 pty、不经 shell**：每条命令是一次独立的请求/响应 RPC，可超时、可取消、可审计，
  也不需要任何流式隧道（绕开了背压与会话续接的全部难题）。
- **agent 不监听端口**：本机没有旁路入口，命令只能来自 gate。
- **cd / pwd / help 不下发**：会话内置，见下文。

## 跑起来

```bash
# 1) 启动 gate（RPC :8991 + Web :8080）
go run ./examples/ops/cmd/gate

# 2) 启动 agent（另开一个终端）
go run ./examples/ops/cmd/agent -name web01 -addr localhost:8991 -root .

# 3) 浏览器打开 http://localhost:8080/
```

冒烟：`pwd` → `ls` → `cd internal` → `ls` → `help`（看这台机器这个档位能敲什么），
再敲 `rm -rf x`（拦截）。放行与拒绝都会出现在右侧审计面板里。

## 目录

| 路径 | 作用 |
|---|---|
| `cmd/gate` | 管控端：sloth 服务端 + HTTP API + Web 页面 |
| `cmd/agent` | 被管端：sloth 客户端 + `ops.Exec` / `ops.Output` |
| `internal/policy` | 策略引擎：默认拒绝 + 白名单 + 禁止 shell 元字符 |
| `internal/policy/translate.go` | 统一命令层：Linux 命令 → Windows 命令的确定性翻译（174 条对照） |
| `internal/audit` | 审计：append-only JSONL + 内存 ring |
| `internal/ops` | 执行器：argv 执行、进程树终止、输出分片 |

## 当前状态（M1 骨架）

已落地：

- 机器注册（`v1.Sign` / `v1.Reg`）、在线列表、断线重连后自动重新注册
- `ops.Exec` / `ops.Output` / `ops.Resolve`（输出分片接口已就绪，页面暂未分页拉取）
- 平台感知：agent 注册时上报 `runtime.GOOS`，gate 按平台选规则集并决定执行方式
- 策略引擎：默认拒绝 + 三档规则集 + 参数级拒绝（见下）
- **统一命令层**：Linux 是唯一入口，Windows 上翻译后执行（174 条对照）
- **会话内置命令**：`cd` / `pwd` / `help` 不下发，`cd` 越界由 agent 的 `-root` 判
- `help`：列出当前机器 + 档位的 allow/deny 规则（Windows 上附完整对照表）
- 审计：`./audit.jsonl`，放行与拒绝都记，页面展示最近 50 条
- 超时 + 进程树终止（Windows 用 `taskkill /T`，其它用进程组 `kill -PGID`）

还没做（按优先级）：

- [ ] 账号系统对接 LDAP / OAuth / SSO（现在是内置账号表，`authn.Authenticator` 接口已抽出）
- [ ] 会话持久化（现在在进程内，gate 重启即登出；cwd 也会一起丢）
- [ ] 文件操作 `ops.Upload` / 在线编辑（替代 vim）
- [ ] 脚本模板（替代管道与多行命令）
- [ ] 翻译层覆盖 PowerShell 侧的高级参数（现在只翻最常用的 flag，其余丢弃）
- [ ] 输出分片的前端分页拉取（现在只显示前 8KB）
- [ ] 审计落库（Postgres）+ 大输出对象存储 + 防篡改归档
- [ ] 传输加密：默认 `tcp` 是明文，生产换 `quic`（强制 TLS）或给 tcp 包一层 `tls.Conn`

## 统一命令层：Linux 是唯一入口

不管 agent 跑在 Linux 还是 Windows，**人敲的都是 Linux 命令**。对照表覆盖运维常用命令
（文件与目录、查看与内容处理、压缩、信息显示、搜索、用户、网络、磁盘、权限、进程、
系统管理、内置命令这些类目），Windows 上在策略判定之后做一次确定性翻译：

```
用户输入（Linux 命令）
   → Linux 规则集判定（唯一入口，档位在这里生效）
   → 翻译层（Linux → PowerShell，只填"值"，模板固定）
   → Windows 规则集复核翻译产物
   → powershell.exe -NoProfile -NonInteractive -Command <argv>
```

为什么不做"两套白名单"（Windows 让人敲 `Get-*`）：人会串台，规则会有两套真相，改一处忘一处；
更实际的是审计里同一次操作在不同机器上是两个名字，排查时对不齐。

翻译是**确定性模板**：用户输入只作为路径/pattern 等"值"填进去，而值已被 Linux 规则集的参数
正则约束过，`ParseLine` 又拒掉了 `; | & $` 反引号 `()`——所以模板里的管道（如
`ls -l` → `Get-ChildItem | Format-Table`）不会被用来接第二条命令。复核那一步是给翻译表买的保险：
模板万一吐出 `Remove-Item`，Windows 规则集会拦下。

Windows 上没有 `ls`/`cat`/`grep` 这些可执行文件，`dir`/`type` 又是 cmd 内置（exec 找不到），
所以执行器必须包一层 PowerShell。安全性**不靠这层包装**，靠上面那三道闸。

### 对照表（节选，完整表在页面的 `help` 里，174 条）

| 敲这个 | Windows 上实际跑 | | 敲这个 | Windows 上实际跑 |
| --- | --- | --- | --- | --- |
| `ls` | `Get-ChildItem` | | `ps` | `Get-Process` |
| `ls -l` | `Get-ChildItem \| Format-Table` | | `kill 123` | `Stop-Process -Id 123` |
| `cat a.log` | `Get-Content -Path a.log` | | `pkill nginx` | `Stop-Process -Name nginx` |
| `head -n 20 a.log` | `Get-Content -Path a.log -TotalCount 20` | | `systemctl status x` | `Get-Service -Name x` |
| `tail -n 20 a.log` | `Get-Content -Path a.log -Tail 20` | | `service x restart` | `Restart-Service -Name x` |
| `grep err a.log` | `Select-String -Pattern err -Path a.log` | | `df -h` | `Get-PSDrive -PSProvider FileSystem` |
| `grep -r err /data` | `Get-ChildItem -Recurse -File \| Select-String` | | `du -sh .` | `Get-ChildItem -Recurse -File \| Measure-Object` |
| `find . -name *.log` | `Get-ChildItem -Recurse -Filter` | | `free` | `Get-CimInstance Win32_OperatingSystem \| Select-Object` |
| `wc -l a.log` | `Get-Content \| Measure-Object -Line` | | `uname -a` | `Get-CimInstance Win32_OperatingSystem \| Select-Object` |
| `which nginx` | `Get-Command -Name nginx` | | `uptime` | `Get-CimInstance … \| Select-Object LastBootUpTime` |
| `ping -c 4 h` | `ping -n 4 h` | | `ip addr` | `Get-NetIPConfiguration` |
| `netstat -tulpn` | `Get-NetTCPConnection` | | `dig a.com` | `Resolve-DnsName -Name a.com` |
| `rm -rf /data/tmp/x` | `Remove-Item -Recurse -Force` | | `mkdir -p /data/x` | `New-Item -ItemType Directory -Force` |

实测（Windows agent，view 档）：

```
pwd / ls / grep version go.mod / head -n 3 go.mod / wc -l go.mod   allow，真跑出结果
find . -name *.go / ps / df / hostname / date                      allow，真跑出结果
top            => deny/deny-interactive        需要终端
rm -rf x       => deny/deny-rm                 当前档位
Get-ChildItem  => deny/default                 统一入口：不许直接敲 Windows 命令
```

### 每条命令都要付的"启动税"

`ls` 敲下去要等两秒，**不是策略判定、不是 RPC**：钱全花在 PowerShell 进程启动上。
实测（同一台机器，`-NoProfile -NonInteractive -Command 1`，即空命令）：

| 执行方式 | 耗时 |
| --- | --- |
| `powershell.exe`（5.1） | ~1.6s（.NET Framework 冷启动，与命令内容无关） |
| `powershell.exe -MTA` | ~1.4s |
| `pwsh.exe`（7） | ~0.25s |
| `cmd.exe /c` | ~0.04s |

（顺带排掉两个猜想：清空 `PSModulePath` 没用；`-MTA` 只省 10%。）

所以 agent 优先用 **pwsh 7**，机器上没装才回退 5.1——功能不变，只是慢。
选了哪个会在 agent 启动日志里打印（`powershell=...`）。没装 pwsh 又要根治，只剩两条路，
都是设计层面的取舍，没做：

- **`cmd /c` 快路径**：`ls`→`dir`、`cat`→`type` 这类走 cmd（40ms）。代价是引入 cmd 的
  元字符解析（`%VAR%`、`^`），等于多一层要守的面；
- **常驻 PowerShell 进程**：命令走 stdin 喂进去（~10ms）。代价是状态污染（变量/CD 残留）、
  卡住要重启进程，等于放弃"每条命令一个独立进程、可超时可杀"的隔离性。

**做不到的事明说**，而不是让 PowerShell 报一堆红字。`top`、`vim`、`less`、`watch` 需要终端（没有 pty）；
`tar`/`zip` 解压会覆盖文件；`lsof`、`crontab`、`xargs` 在 Windows 上没有对应物；
`chmod`/`chown`、`mount`/`mkfs`、`ssh`/`curl` 属于变更类，规则集直接 deny。
敲这些会看到：`top: 该命令在 Windows 上没有对应实现；可改用 ps（Get-Process）——实时刷新需要终端`。

两条红线：

1. **绝不放 PowerShell alias**。`del`→`Remove-Item`、`copy`→`Copy-Item`、`curl`/`wget`→`Invoke-WebRequest`，
   alias 一进白名单等于把删除和下载都开了。
2. **翻译模板只取位置参数，不认识的 flag 直接丢**。`cat a.log -Wait` 里的 `-Wait` 不会被翻成长驻跟踪——
   宁可少给一个参数，也不猜用户意图。

### 规则集怎么分层

判定只有一套（Linux 集），但分四层，从上到下命中即生效：

| 层 | 作用 | 例子 |
| --- | --- | --- |
| `baseDenyRules` | 任何档位都拒：变更/高危 | 关机、权限、账号、解释器、下载、磁盘、跟踪、脱离控制 |
| `interactiveDenyRules` | 需要终端 | `top` `vim` `less` `watch` `man` |
| `argDenyRules` | 命令可放行、某几个参数不行 | `find -delete` / `-exec`、`tail -f`、`ip addr add` |
| `viewRules` → `opsRules` → `adminRules` | 按档位叠加 | 只读 → 服务起停/杀进程 → 受限写删 |

路径规则同时接受 `/data/tmp/x` 与 `C:\data\tmp\x`——入口统一了，但 Windows 上人只能敲盘符。
真正的边界不在这里，在 agent 的 `-root`：那是唯一真相，不再写第二份。

## 会话内置命令：cd / pwd

`cd` 没有可执行文件（是 shell 内置，Windows 上没有 cd.exe、Linux 上也没有），
`pwd` 交给子进程跑同样没意义——工作目录本来就是状态。所以这两条由 gate 自己处理：

- cwd 记在**会话**里（用户 × 机器分开，切机器不会串目录），`cd` 只改状态、**不下发任何命令**；
- 越界判断**不放在 gate**：它不知道 agent 的 `-root`，另写一套规则必然与 agent 不一致
  （两边都判 = 两套真相）。`cd` 只调一次 `ops.Resolve`，由 agent 判——它才是知道边界的那个人，
  而且只回路径、不起进程：

```
$ cd C:\Windows
cd: cwd C:\Windows is outside allowed root D:\...\sloth-proxy
```

- 提示符显示 `机器:目录 $`；切换机器会自动 `pwd` 一次。

### 基础命令（view 档就有）

**只列 Linux 命令**：Windows 上敲同样的名字，翻译层负责落地（右列是实际跑的东西，
不是让人敲的）。

| 意图 | 敲这个 | Windows 上实际跑 |
| --- | --- | --- |
| 当前目录 / 切目录 | `pwd` / `cd <dir>` | 会话内置（不下发）；`cd C:\..`、`cd ..` 都认 |
| 列目录 | `ls` | `Get-ChildItem` |
| 读文件 | `cat <path>` | `Get-Content -Path` |
| 搜文本 | `grep` | `Select-String` |
| 看进程 | `ps` | `Get-Process` |
| 看端口 | `netstat -tulpn` / `ss -lntp` | `Get-NetTCPConnection` |
| 看服务 | `systemctl status x` | `Get-Service -Name x` |
| 磁盘与容量 | `df` / `du -sh p` | `Get-PSDrive` / `Get-ChildItem \| Measure-Object` |
| 文件属性 / 数行数 | `stat` / `wc -l` | `Get-Item` / `Get-Content \| Measure-Object` |
| 找命令 / 找文件 | `which x` / `find p -name x` | `Get-Command x` / `Get-ChildItem -Filter x` |
| 看网卡 | `ifconfig` / `ip addr` | `Get-NetIPConfiguration` |

统一入口的代价：**Windows 上敲 `dir`、`type`、`findstr`、`Get-ChildItem` 一律拒绝**——
它们不在 Linux 规则集里。这是刻意的：放开它们就回到两套名字的老路。
想看 Windows 原生命令长什么样，敲 `help` 看对照表。

补齐命令时守住的红线（都有测试盯着）：

- `ip` 只放 show 类子命令——`ip addr add` 是改网络，落默认拒绝；
- `find` 只放 `-maxdepth` / `-type` / `-name`——`-exec` 与 `-delete` 一律默认拒绝；
- `tail` 拒 `-f`（长驻）、`top`/`vim`/`less`/`watch` 拒（需要 pty）。

## 测试

```bash
go test ./examples/ops/internal/policy/
```

覆盖：Linux 规则集（档位分层、路径两种写法）、Windows 复核（翻译产物白名单 + 管道每一段）、
翻译映射正确性、`无对应实现必须给替代命令`、危险输入拒绝（`tail -f` / `find -delete` / `ip addr add`）、
对照表每条都要有落点、`ParseLine` 元字符、正则锚点与 `.exe` 后缀归一化。

## 为什么不做真 pty

审计是红线。真 pty 之后服务端只看到字节流，只能"录屏"，拦不住命令；
端到端加密的 SSH 隧道同理。要"能干什么、不能干什么"，就必须有一端拿到
**明文命令**并且**不给完整 shell**——这是本项目的取舍：牺牲 vim / tmux / 管道，
换取命令级拦截与结构化审计。
