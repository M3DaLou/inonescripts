# vps-netcheck.sh

Debian VPS **出网一键体检**。在节点本机运行，检查「这台机器访问外网」是否正常。

默认只体检、不改系统。修复、流媒体解锁、Telegram、指定 IP 网络质量都是可选功能。

当前版本：**1.5.0**

---

## 它测的是什么、不测什么

| 测得到 | 测不到 |
| --- | --- |
| 这台 VPS 自己访问外网（DNS、ICMP、HTTPS、带宽、路由） | 用户穿过节点后的体感（入口线路、客户端到节点） |
| 到指定 IP 的延迟、丢包、路由质量 | 对端业务端口是否「该开却没开」（质量测试里 TCP 只试 443/80） |
| 到 Telegram 机房 / 官网是否被单独限速 | App 里某条视频 CDN 的精确路径 |

本机体检全绿、用户走代理仍卡 → 多半是入口线路或节点负载，不是出网挂了。

---

## 环境要求

- 系统：Debian / Ubuntu（用 `apt`）
- 建议 **root** 运行（缺工具时才能自动安装；root 下 ping/mtr 间隔可以更短）
- 需要能执行：`bash`、`curl`、`ping`；完整模式还要 `traceroute`；网络质量还要 `mtr`（缺了会尝试装 `mtr-tiny`）

结果会写到：

```text
/tmp/vps-netcheck-时间戳.log
```

---

## 快速开始

把脚本拷到 VPS 上，然后：

```bash
# 推荐：SSH 上去直接回车，进交互菜单
bash vps-netcheck.sh

# 看全部命令行参数
bash vps-netcheck.sh --help
```

非交互终端（管道、部分面板「一键执行」）不会出菜单，请改用命令行参数，或加 `--interactive`（仍需要真正的交互终端）。

---

## 交互菜单

| 序号 | 做什么 | 会不会跑网络体检 |
| --- | --- | --- |
| 1 | 网络体检（推荐） | 会 |
| 2 | 网络体检 + 流媒体解锁 | 会 |
| 3 | 只测流媒体解锁 | 不会 |
| 4 | 只测 Telegram | 不会 |
| 5 | 指定 IP 网络质量（路由 / 延迟 / 丢包） | 不会 |
| 6 | 修复（关 IPv6 / 改 MTU / 改 DNS 等） | 可选 |
| 7 | 看命令行帮助 | — |
| q | 退出 | — |

选 1 / 2 时还会问：

- **深度**：快速 / 默认 / 完整（见下方「体检深度」）
- 要不要加测某个特别卡的网址
- 要不要加测 Telegram
- 要不要指定 DNS（只影响这一轮脚本，不改系统）
- 体检结束后若发现问题，要不要逐项询问修复

---

## 网络体检

### 体检深度

| 模式 | 参数 | 大约耗时 | 内容 |
| --- | --- | --- | --- |
| 快速 | `--quick` | ~40 秒 | 跳过测速、traceroute |
| 默认 | （不加） | 1–2 分钟 | 常规项 + 粗测速 |
| 完整 | `--full` | 更久 | 默认 + traceroute |

### 体检会检查什么

1. **依赖**：缺 `curl` / `ping` / `dig` 等时尝试 `apt` 安装（`--no-install` 则跳过）
2. **本机概况**：负载、内存、磁盘（机器本身很忙时，卡不一定是网络）
3. **系统时间**：时钟不准会导致 HTTPS/TLS 失败
4. **网卡 / 路由 / 公网身份**：出网网卡、默认路由、公网 IPv4/IPv6
5. **DNS**：解析是否慢、是否像被劫持；UDP/53 不通时看 TCP 能否解析
6. **ICMP**：对 `1.1.1.1` / `8.8.8.8` 等 ping，看丢包和延迟（机房常禁 ping，失败不代表 TCP 不通）
7. **MTU**：大包 Don't Fragment 探测（部分网站加载到一半失败的常见原因）
8. **IPv6**：有地址但出不了网的「半残 IPv6」，会导致有 AAAA 的站卡住
9. **常见端口**：本机监听、出站是否被拦
10. **分站点 HTTPS**：DNS / TCP / TLS / TTFB，最能对上「只有部分网站不顺」
11. **下载测速**（非 quick）：Cloudflare / Cachefly，粗看带宽
12. **路由追踪**（仅 `--full`）：看是否绕路、中途黑洞
13. **连接数**：用户多或被扫端口时，连接表会把新连接拖慢

### 常用命令

```bash
# 默认体检
bash vps-netcheck.sh --quick          # 只要快
bash vps-netcheck.sh                  # 无参数且在 SSH 里 = 菜单
bash vps-netcheck.sh --full           # 加上 traceroute

# 加测用户说卡的网站（可重复）
bash vps-netcheck.sh --url https://www.netflix.com
bash vps-netcheck.sh --url https://a.com --url https://b.com

# 从文件读额外网址（一行一个，# 开头当注释）
bash vps-netcheck.sh --file /root/sites.txt

# 这一轮检测改用指定 DNS（不改系统）
bash vps-netcheck.sh --dns 1.1.1.1,8.8.8.8

# 缺工具时不要自动 apt
bash vps-netcheck.sh --no-install
```

---

## 指定 IP 网络质量（独立于体检）

用来回答：「到这几个 IP，路由好不好、延迟多少、丢不丢包？」

**不会**跑完整网络体检（系统时间、HTTPS 站点表、测速等都跳过）。

### `--quality-count` 是什么

每个目标会做两类重复探测，`--quality-count N` 就是 **每类重复 N 次**（允许 5–100，默认 **20**）：

| 项目 | 次数的含义 |
| --- | --- |
| ICMP ping | 连续 ping N 次，用来算丢包率、min/avg/max、抖动 |
| mtr | 对整条路径循环 N 个周期，用来算 **每一跳** 的丢包和延迟 |

所以：

```bash
bash vps-netcheck.sh --quality-only 1.1.1.1 --quality-count 30
```

表示：对 `1.1.1.1` 做 **30 次 ping + 30 个周期的 mtr**，不是「测 30 个 IP」。

次数越大：

- 丢包、抖动越准（偶发 1 个丢包在 20 次里是 5%，在 30 次里约 3%）
- 越慢：每个目标大约要 **2 × N 秒**（root 下间隔更短，会快一些）
- 测 3 个 IP、`--quality-count 30`，大约数分钟

建议：日常 20；要拍板「到底有没有丢包」用 50–100。

### 每个目标会输出什么

1. **ICMP**：丢包、min / avg / max、jitter（抖动）
2. **TCP**：先试 443，不通再试 80（目标没开这两个端口 ≠ 网络不通）
3. **路由**：优先 `mtr`（每跳 Loss% / Avg）；没有 mtr 才用 traceroute  
   ICMP 全丢时自动改走 **TCP mtr**（很多机房禁 ping）

最后有一张汇总表：目标、丢包、ICMP 均延、抖动、TCP 均延、跳数、是否到达。

### 怎么看结果

- **丢包**：看 ping 和 mtr **末跳**。中间跳的 Loss% 经常是假的（设备限 ICMP）
- **延迟**：看 ICMP avg；和 TCP 差很多时，以能通的那一侧为准
- **抖动大**：排队、回程不稳或国际线路抖，表现为时快时慢
- **路由**：跳数突然很多、回国再出国、连续 `???` → 绕路或黑洞
- **ICMP 全丢但 TCP 正常** → 机房禁 ping，不是目标挂了
- **第一跳丢包很高、后面却正常** → 多半是网关限 ICMP，可忽略

### 命令

```bash
# 只测质量，不跑体检（推荐）
bash vps-netcheck.sh --quality-only 1.1.1.1,8.8.8.8
bash vps-netcheck.sh --quality-only 1.1.1.1 8.8.8.8 223.5.5.5

# 更准、更慢
bash vps-netcheck.sh --quality-only 1.1.1.1 --quality-count 30

# 业务对端 / IPv6 / 域名都可以
bash vps-netcheck.sh --quality-only 203.0.113.10,2001:4860:4860::8888
bash vps-netcheck.sh --quality-only www.google.com

# 先体检，再加测这些 IP
bash vps-netcheck.sh --quality 1.1.1.1,8.8.8.8
```

交互菜单选 **5**，按提示填 IP 和探测次数即可。

---

## Telegram

用来排除「是不是 Telegram 服务器自己慢 / 到 TG 网段被单独限速」。

测的是 **本机直连** Telegram，不是用户穿过节点的体感。官方 DC 入口 IP 会变，某个 IP 连不上时先看其它 DC 和官网下载。

会做：

- Cloudflare 10MB 对照下载
- Telegram 安装包下载
- `telegram.org` HTTPS
- 五个官方机房 TCP 443（日本节点重点看 DC5 新加坡）+ ICMP（TG 机房常禁 ping，不算坏）

```bash
bash vps-netcheck.sh --telegram            # 体检后再测
bash vps-netcheck.sh --telegram-only       # 只测 Telegram
```

怎么看：

- Cloudflare 和 TG 安装包都慢 → 这条线整体慢，不是 TG 独有
- Cloudflare 很快、TG 安装包很慢 → 到 TG 网段被限或绕路
- 五个 DC 大多连不上 → 出站被拦或到 TG 网段全挂
- 个别 DC 连不上、其它正常 → 入口 IP 会变，一般不能说明「TG 全球挂了」

---

## 流媒体解锁

调用第三方 [lmc999/RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck)，按需下载，不改系统。

```bash
bash vps-netcheck.sh --unlock                          # 体检后再跑
bash vps-netcheck.sh --unlock-only                     # 只跑流媒体
bash vps-netcheck.sh --unlock-only --unlock-region 2   # 跨国 + 香港
bash vps-netcheck.sh --unlock-only --unlock-ip 4       # 只测 IPv4（推荐）
bash vps-netcheck.sh --list-unlock-regions             # 列出区域编号
```

| `--unlock-ip` | 含义 |
| --- | --- |
| `4` | 只测 IPv4（默认；半残 IPv6 的机器请用这个） |
| `6` | 只测 IPv6 |
| `0` | IPv4 + IPv6 都测 |

| `--unlock-region` | 含义 |
| --- | --- |
| `a` / `auto` | 按这台机器 IP 归属自动选（推荐） |
| `0` | 只测跨国平台（Netflix、Disney+、YouTube、ChatGPT 等，较快） |
| `1` | 跨国 + 台湾 |
| `2` | 跨国 + 香港 |
| `3` | 跨国 + 日本 |
| `4` | 跨国 + 北美 |
| `5` | 跨国 + 南美 |
| `6` | 跨国 + 欧洲 |
| `7` | 跨国 + 大洋洲 |
| `8` | 跨国 + 韩国 |
| `9` | 跨国 + 东南亚 |
| `10` | 跨国 + 印度 |
| `11` | 跨国 + 非洲 |
| `66` | 全部平台（最全，也最慢） |
| `88` | Instagram 音乐 |
| `99` | 体育直播 |

`--dns` 也会影响解锁脚本的解析（尽量不改系统 resolv.conf）。

---

## 可选修复

默认不执行。改系统前会再问一声；自动化时加 `--yes` 才跳过确认。

| 参数 | 作用 |
| --- | --- |
| `--fix` | 体检结束后，对发现的问题逐项询问是否修复 |
| `--fix-ipv6` | 持久关闭 IPv6（写 `sysctl.d`，重启仍生效） |
| `--undo-ipv6` | 撤销本脚本写过的「关闭 IPv6」 |
| `--fix-ipv4-pref` | 出站优先 IPv4（改 `gai.conf`，不关 IPv6；半残 IPv6 更推荐这个） |
| `--undo-ipv4-pref` | 撤销「出站优先 IPv4」 |
| `--fix-mtu [N]` | 把默认网卡 MTU 改为 N（默认 1400）并开机保持 |
| `--fix-mss` | 加上 TCP MSS 钳位（配合偏低的 MTU） |
| `--undo-mss` | 撤销 MSS 钳位 |
| `--fix-dns` | 把系统 DNS 改成 `--dns` 指定的地址（**影响整机，慎用**） |
| `--flush-dns` | 刷新本机 DNS 缓存 |
| `--fix-ntp` | 打开 NTP，同步系统时钟 |
| `--yes` | 修复类操作不再询问 |

```bash
# 最稳：先体检，再逐项问
bash vps-netcheck.sh --fix

# 半残 IPv6：不关 IPv6，只让出站优先 IPv4
bash vps-netcheck.sh --fix-ipv4-pref --yes

# 撤销
bash vps-netcheck.sh --undo-ipv4-pref --yes
bash vps-netcheck.sh --undo-ipv6 --yes
bash vps-netcheck.sh --undo-mss --yes

# 改系统 DNS 必须同时指定 --dns
bash vps-netcheck.sh --fix-dns --dns 1.1.1.1,8.8.8.8 --yes
```

交互菜单选 **6** 也可以做同样的事。

---

## 结果怎么对照「只有部分网站不顺」

先看 **FAIL**，再看 **WARN**。

| 现象 | 常见原因 |
| --- | --- |
| 有 AAAA 的站（Google / Facebook / GitHub）慢，纯 IPv4 正常 | IPv6 半残 → 优先 `--fix-ipv4-pref` |
| 小站正常，大站 / 登录 / 视频加载到一半失败 | MTU 偏大 → `--fix-mtu`，必要时再 `--fix-mss` |
| 所有站先转圈，或个别站解析到奇怪 IP | DNS 慢或劫持 → 先 `--dns` 对比，确认后再考虑 `--fix-dns` |
| 只有某几家 403 / 人机验证，其它很快 | 机房 IP 被目标站风控 |
| 表里只有某几个站 TCP/TLS 特别慢 | 到那一段网段绕路 → 用 `--quality-only` 对着对端 IP 细测 |
| 本机体检全绿，用户走代理仍卡 | 入口线路 / 节点负载（本脚本测不到） |
| Telegram 卡 | `--telegram-only`，对照 Cloudflare 和五个 DC |
| 到某几个业务 IP 卡 | `--quality-only IP1,IP2` |

---

## 命令行速查

```text
用法:
  bash vps-netcheck.sh              # 交互菜单（推荐）
  bash vps-netcheck.sh [选项]

体检:
  --quick / --full
  --url URL
  --file FILE
  --dns IP[,IP...]
  --no-install

流媒体:
  --unlock / --unlock-only
  --unlock-region N
  --unlock-ip 4|6|0
  --list-unlock-regions

Telegram:
  --telegram / --telegram-only

指定 IP 质量:
  --quality IP[,IP...]
  --quality-only IP[,IP...]
  --quality-count N          # ping / mtr 次数，默认 20

修复:
  --fix
  --fix-ipv6 / --undo-ipv6
  --fix-ipv4-pref / --undo-ipv4-pref
  --fix-mtu [N]
  --fix-mss / --undo-mss
  --fix-dns                  # 必须同时 --dns
  --flush-dns
  --fix-ntp
  --yes

其它:
  --interactive
  -h, --help
```

---

## 组合例子

```bash
# 快速体检 + 指定 DNS + 加测一个站
bash vps-netcheck.sh --quick --dns 1.1.1.1 --url https://www.google.com

# 体检 + Telegram + 流媒体（香港）
bash vps-netcheck.sh --telegram --unlock --unlock-region 2 --unlock-ip 4

# 只关心到业务 IP 的线路
bash vps-netcheck.sh --quality-only 203.0.113.10,203.0.113.11 --quality-count 50

# 体检完若有问题再问要不要修
bash vps-netcheck.sh --full --fix
```

---

## 注意

- 改系统的操作（IPv6 / MTU / DNS / MSS / NTP）都会再确认；不要在不了解影响时对生产机加 `--yes`。
- `--fix-dns` 会影响整机解析，不只是这一轮脚本。
- 流媒体结果来自第三方脚本，和本仓库的网络判断是两套东西。
- 质量测试里的 TCP 只用来量延迟，不表示目标「应该」提供网页。
